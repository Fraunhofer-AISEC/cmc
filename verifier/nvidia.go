// Copyright (c) 2026 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verifier

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
)

var (
	sha384Pool sync.Pool

	chainCache   = make(map[string]cachedChainEntry)
	chainCacheMu sync.RWMutex
)

// chainCacheTTL caps how long a verified chain is served from cache so that
// revoked-but-not-yet-expired certificates cannot be served indefinitely.
const chainCacheTTL = 5 * time.Minute

type cachedChainEntry struct {
	certs     []*x509.Certificate
	expiresAt time.Time
}

func init() {
	sha384Pool = sync.Pool{
		New: func() interface{} {
			return sha512.New384()
		},
	}
}

type GpuArchitectureName int

const (
	Hopper GpuArchitectureName = iota
	Blackwell
	Invalid
)

type GpuArchitectureData struct {
	architecture GpuArchitectureName
	signatureLen int
}

func CreateGpuArchitectureData(name string) GpuArchitectureData {
	switch name {
	case "HOPPER":
		return GpuArchitectureData{Hopper, 96}
	case "BLACKWELL":
		return GpuArchitectureData{Blackwell, 96}
	}
	return GpuArchitectureData{Invalid, 0}
}

func ToHexString(data []byte) string {
	return hex.EncodeToString(data)
}

const (
	// nvdec0MeasurementIndex is the measurement block covering the NVDEC0 engine.
	// It is only meaningful when the engine is enabled.
	nvdec0MeasurementIndex = 35

	// nvdec0StatusDisabled is the value NVIDIA reports in the NVDEC0 status opaque
	// field when the engine is disabled, in which case block 35 must be skipped.
	nvdec0StatusDisabled = 0x55
)

// verifyCertificateChain verifies the PEM encoded certificate chain, leaf first, against the
// root CAs identified by caFingerprints. NVIDIA chains carry their own self-signed root, which
// is trusted only if its fingerprint is pinned by the signed metadata
func verifyCertificateChain(chainPEM string, caFingerprints []string) error {
	// The cache key must cover the accepted roots as well as the chain. Keyed on the chain
	// alone, a chain verified under one trust anchor would be served from cache for a query
	// under a different one, e.g. a device chain would pass as a RIM signing chain
	cacheKey := strings.Join(caFingerprints, ",") + "\x00" + chainPEM

	chainCacheMu.RLock()
	entry, found := chainCache[cacheKey]
	chainCacheMu.RUnlock()

	if found {
		if now().After(entry.expiresAt) {
			chainCacheMu.Lock()
			delete(chainCache, cacheKey)
			chainCacheMu.Unlock()
		} else {
			currentTime := now()
			if currentTime.Before(entry.certs[0].NotBefore) || currentTime.After(entry.certs[0].NotAfter) {
				return fmt.Errorf("cached certificate chain has expired")
			}
			return nil
		}
	}

	var certificates []*x509.Certificate
	rest := []byte(chainPEM)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return errors.New("no certificates found in the provided chain string")
	}

	leafCert := certificates[0]

	root, err := internal.SelfSignedRoot(certificates)
	if err != nil {
		return fmt.Errorf("failed to determine root of certificate chain: %w", err)
	}
	if _, err := internal.MatchCaFingerprint(root, caFingerprints); err != nil {
		return fmt.Errorf("root CA %q of the certificate chain is not trusted: %w",
			root.Subject.CommonName, err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediatePool := x509.NewCertPool()
	if len(certificates) > 1 {
		for _, cert := range certificates[1:] {
			intermediatePool.AddCert(cert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatePool,
		CurrentTime:   now(),
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("chain verification error: %w", err)
	}

	chainCacheMu.Lock()
	chainCache[cacheKey] = cachedChainEntry{
		certs:     certificates,
		expiresAt: now().Add(chainCacheTTL),
	}
	chainCacheMu.Unlock()

	return nil
}

func VerifyCertChainSignature(pubKey *ecdsa.PublicKey, rawSignature []byte, message []byte) error {
	sigLen := len(rawSignature)
	if sigLen == 0 || sigLen%2 != 0 {
		// The report carries the raw r||s form, so the length must split evenly
		return fmt.Errorf("raw ECDSA signature length must be even and non-zero, got %d", sigLen)
	}

	half := sigLen / 2
	r := new(big.Int).SetBytes(rawSignature[:half])
	s := new(big.Int).SetBytes(rawSignature[half:])

	h := sha384Pool.Get().(hash.Hash)
	h.Reset()
	h.Write(message)
	digest := h.Sum(nil)
	sha384Pool.Put(h)

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return errors.New("ECDSA signature is invalid")
	}

	return nil
}

func extractNvidiaCollateral(collateral ar.Collateral) *ar.NvidiaCollateral {
	for i := range collateral.Artifacts {
		if collateral.Artifacts[i].Type == ar.TYPE_NVIDIA_COLLATERAL {
			for j := range collateral.Artifacts[i].Events {
				if collateral.Artifacts[i].Events[j].NvidiaCollateral != nil {
					return collateral.Artifacts[i].Events[j].NvidiaCollateral
				}
			}
		}
	}
	return nil
}

// anchorDeviceChain checks that the device certificate chain supplied with the evidence
// chains to one of the NVIDIA device identity root CAs pinned by the signed metadata.
func anchorDeviceChain(chain []*x509.Certificate, caFingerprints []string) error {
	if len(chain) == 0 {
		return errors.New("no device certificates provided for verification")
	}

	pemBuf := new(strings.Builder)
	for _, cert := range chain {
		if err := pem.Encode(pemBuf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return fmt.Errorf("failed to re-encode certificate to PEM: %w", err)
		}
	}
	if err := verifyCertificateChain(pemBuf.String(), caFingerprints); err != nil {
		return fmt.Errorf("device certificate chain does not chain to trusted root: %w", err)
	}

	return nil
}

func VerifyDeviceCerts(collateral ar.Collateral, chain []*x509.Certificate, deviceUUID string,
	caFingerprints []string,
) error {
	if collateral.Type != ar.TYPE_EVIDENCE_NVIDIA {
		return fmt.Errorf("unsupported collateral type: %s", collateral.Type)
	}

	nvidiaCollateral := extractNvidiaCollateral(collateral)
	if nvidiaCollateral == nil {
		return errors.New("nvidia collateral artifacts not found in the payload")
	}

	// Anchoring is repeated here so that the exported function remains a complete
	// check on its own. The result is served from chainCache when VerifyNvidia has
	// already anchored the same chain
	if err := anchorDeviceChain(chain, caFingerprints); err != nil {
		return err
	}

	ocspResponses := nvidiaCollateral.OcspResponsesDeviceCerts
	if len(ocspResponses) == 0 {
		return errors.New("no OCSP responses provided in collateral")
	}

	deviceKey := "device_" + deviceUUID
	deviceOCSP, exists := ocspResponses[deviceKey]
	if !exists {
		return fmt.Errorf("no OCSP response available for device %q", deviceUUID)
	}

	if len(deviceOCSP) > len(chain)-1 {
		return fmt.Errorf("not enough certificates in chain (%d) to verify OCSP responses", len(chain))
	}

	return VerifyCertificateChainWithOCSP(deviceOCSP, chain, true)
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

// compareVersions performs a numeric component-wise comparison of two dotted
// version strings. It returns -1, 0, or 1. Using numeric comparison prevents
// lexicographic ordering bugs such as "530.9" > "530.10".
func compareVersions(v1, v2 string) (int, error) {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			val, err := strconv.Atoi(parts1[i])
			if err != nil {
				return 0, fmt.Errorf("invalid version component %q in %q", parts1[i], v1)
			}
			n1 = val
		}
		if i < len(parts2) {
			val, err := strconv.Atoi(parts2[i])
			if err != nil {
				return 0, fmt.Errorf("invalid version component %q in %q", parts2[i], v2)
			}
			n2 = val
		}
		if n1 < n2 {
			return -1, nil
		}
		if n1 > n2 {
			return 1, nil
		}
	}
	return 0, nil
}

// ---------------------------------------------------------------------------
// RIM retrieval
// ---------------------------------------------------------------------------

func GetRIMUnionForVersions(collateral ar.Collateral, driverVersion string, vbiosVersion string,
	requireOCSP bool, caFingerprints []string,
) (internal.RIM, error) {
	driverVersionTrimmed := strings.TrimSpace(driverVersion)
	vbiosVersionTrimmed := strings.TrimSpace(vbiosVersion)
	// The accepted signing roots are part of the key: the same RIM must not be served from
	// cache for a query that pins a different set of RIM signing root CAs
	cacheKey := fmt.Sprintf("%t|%q|%q|%q", requireOCSP, driverVersionTrimmed, vbiosVersionTrimmed,
		strings.Join(caFingerprints, ","))

	rimCacheMu.RLock()
	cached, found := rimCache[cacheKey]
	rimCacheMu.RUnlock()
	if found {
		if now().Before(cached.expiresAt) {
			log.Debugf("Cache HIT for RIM union: %s", cacheKey)
			return cached.rim, nil
		}
		rimCacheMu.Lock()
		delete(rimCache, cacheKey)
		rimCacheMu.Unlock()
	}

	var result internal.RIM

	nvidiaCollateral := extractNvidiaCollateral(collateral)
	if nvidiaCollateral == nil {
		return result, fmt.Errorf("nvidia collateral artifacts not found in payload")
	}

	driverB64, ok := nvidiaCollateral.DriverRIMs[driverVersionTrimmed]
	if !ok {
		return result, fmt.Errorf("no driver rim found for version %s", driverVersionTrimmed)
	}
	rimBytesDriver, err := base64.StdEncoding.DecodeString(driverB64)
	if err != nil {
		return result, fmt.Errorf("failed to decode driver RIM for version %s", driverVersionTrimmed)
	}

	vbiosB64, ok := nvidiaCollateral.VbiosRIMs[vbiosVersionTrimmed]
	if !ok {
		return result, fmt.Errorf("no vbios rim found for version %s", vbiosVersionTrimmed)
	}
	rimBytesbios, err := base64.StdEncoding.DecodeString(vbiosB64)
	if err != nil {
		return result, fmt.Errorf("failed to decode vbios RIM for version %s", vbiosVersionTrimmed)
	}

	parsedDriverRim, err := internal.ParseRIM(rimBytesDriver, "driver_rim_"+driverVersionTrimmed,
		now(), caFingerprints)
	if err != nil {
		return result, fmt.Errorf("failed to parse driver RIM: %v", err)
	}

	// Enforce strict OCSP checking for driver RIM based on policy
	if requireOCSP {
		err = verifyRIMwithOCSP(parsedDriverRim, collateral)
		if err != nil {
			return result, fmt.Errorf("failed to verify driver RIM certs with OCSP: %w", err)
		}
	}

	parsedVbiosRim, err := internal.ParseRIM(rimBytesbios, "vbios_rim_"+vbiosVersionTrimmed,
		now(), caFingerprints)
	if err != nil {
		return result, fmt.Errorf("failed to parse vbios RIM: %v", err)
	}
	if requireOCSP {
		// Enforce strict OCSP checking for VBIOS RIM based on policy
		err = verifyRIMwithOCSP(parsedVbiosRim, collateral)
		if err != nil {
			return result, fmt.Errorf("failed to verify vbios RIM certs with OCSP: %w", err)
		}
	}

	rims := []internal.RIM{parsedDriverRim, parsedVbiosRim}
	rimUnion := internal.MergeRIMs(rims...)

	rimCacheMu.Lock()
	rimCache[cacheKey] = cachedRimEntry{
		rim:       rimUnion,
		expiresAt: now().Add(rimCacheTTL),
	}
	rimCacheMu.Unlock()

	log.Debugf("Cache MISS filled for RIM union: %s", cacheKey)
	return rimUnion, nil
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

// stringInSlice returns true if target is present in the slice.
func stringInSlice(target string, slice []string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// enforceArchitecturePolicy checks that the GPU architecture is permitted.
func enforceArchitecturePolicy(archName string, policy *ar.NvidiaPolicy) error {
	if len(policy.AllowedArchitectures) == 0 {
		return nil // no restriction
	}
	if !stringInSlice(archName, policy.AllowedArchitectures) {
		return fmt.Errorf("GPU architecture %q is not in the allowed list %v",
			archName, policy.AllowedArchitectures)
	}
	return nil
}

// enforceUUIDPolicy checks allowlists and denylists for the device UUID.
func enforceUUIDPolicy(uuid string, policy *ar.NvidiaExtraSecurityPolicy) error {
	if stringInSlice(uuid, policy.DeniedUUIDs) {
		return fmt.Errorf("GPU UUID %q is explicitly denied by policy", uuid)
	}
	if len(policy.AllowedUUIDs) > 0 && !stringInSlice(uuid, policy.AllowedUUIDs) {
		return fmt.Errorf("GPU UUID %q is not in the allowed list", uuid)
	}
	return nil
}

// compareLooseVersions compares two dotted version strings component by component. Components that
// are numeric on both sides are compared as numbers, any other pair falls back to a string
// comparison, which covers the non-numeric inforom image version ("G520.0200.00.04").
// Unlike compareVersions it never fails, because these fields have no single documented format.
func compareLooseVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := max(len(parts1), len(parts2))

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}
		if p1 == p2 {
			continue
		}

		n1, err1 := strconv.Atoi(p1)
		n2, err2 := strconv.Atoi(p2)
		if err1 == nil && err2 == nil {
			if n1 != n2 {
				if n1 < n2 {
					return -1
				}
				return 1
			}
			continue
		}

		if p1 < p2 {
			return -1
		}
		return 1
	}

	return 0
}

// checkNvidiaMinVersion rejects got if it is below minimum. An empty minimum means the
// field is not constrained by the policy.
func checkNvidiaMinVersion(label, got, minimum string) error {
	if minimum == "" {
		return nil
	}
	if compareLooseVersions(got, minimum) < 0 {
		return fmt.Errorf("%s version %q is below the required minimum %q", label, got, minimum)
	}
	return nil
}

func enforceExtraPolicy(evidence *internal.NvidiaDeviceUnsignedEvidence, policy *ar.NvidiaExtraSecurityPolicy) error {
	if policy.RequireSupplementalEvidence && evidence == nil {
		return errors.New("policy requires supplemental evidence which is not present")
	}
	if evidence == nil {
		return nil
	}
	ev := *evidence

	// 1. UUID allowlist / denylist.
	if err := enforceUUIDPolicy(ev.UUID, policy); err != nil {
		return err
	}

	// 2. Minimum version checks
	minChecks := []struct {
		label   string
		got     string
		minimum string
	}{
		{"inforom OEM", ev.InforomOemVersion, policy.InforomOemMinVersion},
		{"inforom ECC", ev.InforomEccVersion, policy.InforomEccMinVersion},
		{"inforom power", ev.InforomPowerVersion, policy.InforomPowerMinVersion},
		{"inforom image", ev.InforomImageVersion, policy.InforomImageMinVersion},
		{"GSP firmware", ev.GspFirmwareVersion, policy.GspFirmwareMinVersion},
	}
	for _, c := range minChecks {
		if err := checkNvidiaMinVersion(c.label, c.got, c.minimum); err != nil {
			return err
		}
	}
	if len(policy.InforomConfigChecksums) > 0 && !stringInSlice(ev.InforomConfigChecksum, policy.InforomConfigChecksums) {
		return fmt.Errorf("info rom Config Checksum %s is not in the allowed list", ev.InforomConfigChecksum)
	}

	// 3. Boolean Policy Enforcement (Pointers evaluated if not nil)
	if policy.RequireGspEnabled != nil && ev.GspFirmwareIsEnabled != *policy.RequireGspEnabled {
		return fmt.Errorf("gcp firmware enabled status mismatch: expected %t, got %t", *policy.RequireGspEnabled, ev.GspFirmwareIsEnabled)
	}
	if policy.RequireGspDefault != nil && ev.GspFirmwareDefault != *policy.RequireGspDefault {
		return fmt.Errorf("gsp firmware default status mismatch: expected %t, got %t", *policy.RequireGspDefault, ev.GspFirmwareDefault)
	}
	if policy.RequireInforomValid != nil && ev.InforomIsValid != *policy.RequireInforomValid {
		return fmt.Errorf("info rom valid status mismatch: expected %t, got %t", *policy.RequireInforomValid, ev.InforomIsValid)
	}

	// 4. MIG Mode Expected Values (Pointers evaluated if not nil)
	if policy.MigCurrentModeExpected != nil && ev.MigCurrentMode != *policy.MigCurrentModeExpected {
		return fmt.Errorf("MIG Current Mode mismatch: expected %d, got %d", *policy.MigCurrentModeExpected, ev.MigCurrentMode)
	}
	if policy.MigPendingModeExpected != nil && ev.MigPendingMode != *policy.MigPendingModeExpected {
		return fmt.Errorf("MIG Pending Mode mismatch: expected %d, got %d", *policy.MigPendingModeExpected, ev.MigPendingMode)
	}

	return nil
}

// nvidiaPolicyFromManifests returns the NVIDIA GPU policy configured across all manifests, or nil
// if none is configured. Reject, if more than one manifest defines a policy.
func nvidiaPolicyFromManifests(metadata []ar.Metadata) (*ar.NvidiaPolicy, error) {
	var policy *ar.NvidiaPolicy
	var name string

	for _, m := range metadata {
		if m.NvidiaPolicy == nil {
			continue
		}
		if policy != nil {
			return nil, fmt.Errorf("manifests %q and %q both define an NVIDIA policy", name, m.Name)
		}
		policy = m.NvidiaPolicy
		name = m.Name
	}

	if policy == nil {
		log.Debug("No NVIDIA GPU policy configured in any manifest")
	} else {
		log.Debugf("Using NVIDIA GPU policy from manifest %q", name)
	}

	return policy, nil
}

// VerifyNvidia verifies NVIDIA GPU evidence against signed metadata
func VerifyNvidia(
	evidence ar.Evidence,
	collateral ar.Collateral,
	nonce []byte,
	manifests []ar.Metadata,
) *ar.MeasurementResult {

	log.Debug("Verifying NVIDIA measurements")

	result := &ar.MeasurementResult{
		Type:         "Nvidia Result",
		NvidiaResult: &ar.NvidiaResult{},
	}
	nvidiaResult := result.NvidiaResult

	// fail records a failure on the individual check which detected it and mirrors it into
	// the summary, which is what relying parties and attestation policies evaluate. Only the
	// check logs, so that a single failure does not produce two identical warnings. Checks
	// which are never reached keep their zero status, they did not fail, they did not run
	fail := func(check *ar.Result, code ar.ErrorCode, err error) {
		check.Fail(code, err)
		result.Summary.Status = ar.StatusFail
		if code != ar.NotSpecified {
			result.Summary.ErrorCodes = append(result.Summary.ErrorCodes, code)
		}
		if check.Details != "" {
			result.Summary.Details = check.Details
		}
	}

	nvidiaPolicy, err := nvidiaPolicyFromManifests(manifests)
	if err != nil {
		fail(&nvidiaResult.PolicyCheck, ar.VerifyPolicies, err)
		return result
	}

	// Both the device identity chain and the RIM signing chain are included the evidence and carry
	// their own self-signed root, which is trusted only if the signed metadata pins its fingerprint
	if nvidiaPolicy == nil {
		fail(&nvidiaResult.PolicyCheck, ar.PolicyNotPresent,
			errors.New("no NVIDIA policy configured in any manifest, cannot determine the trusted root CAs"))
		return result
	}
	if len(nvidiaPolicy.DeviceCaFingerprints) == 0 {
		fail(&nvidiaResult.PolicyCheck, ar.PolicyNotPresent,
			errors.New("NVIDIA policy does not pin any device identity root CA fingerprint"))
		return result
	}
	if len(nvidiaPolicy.RimCaFingerprints) == 0 {
		fail(&nvidiaResult.PolicyCheck, ar.PolicyNotPresent,
			errors.New("NVIDIA policy does not pin any RIM signing root CA fingerprint"))
		return result
	}

	nvidiaExtraSecPolicy := nvidiaPolicy.ExtraSecurityPolicy

	var GPUevidence internal.NvidiaGPUEvidence
	if err := cbor.Unmarshal(evidence.Data, &GPUevidence); err != nil {
		result.Summary.Fail(ar.ParseEvidence, fmt.Errorf("failed to decode NVIDIA GPU evidence: %w", err))
		return result
	}

	archData := CreateGpuArchitectureData(GPUevidence.Architecture)
	if archData.architecture == Invalid {
		result.Summary.Fail(ar.MeasurementTypeNotSupported,
			fmt.Errorf("unrecognised GPU architecture %q", GPUevidence.Architecture))
		return result
	}

	if err := enforceArchitecturePolicy(GPUevidence.Architecture, nvidiaPolicy); err != nil {
		nvidiaResult.PolicyCheck.Got = GPUevidence.Architecture
		nvidiaResult.PolicyCheck.ExpectedOneOf = nvidiaPolicy.AllowedArchitectures
		fail(&nvidiaResult.PolicyCheck, ar.VerifyPolicies,
			fmt.Errorf("architecture policy violation: %w", err))
		return result
	}

	// --- UUID denylist check (fail fast before expensive crypto) -----------
	if nvidiaExtraSecPolicy != nil {
		if err := enforceUUIDPolicy(GPUevidence.UUID, nvidiaExtraSecPolicy); err != nil {
			nvidiaResult.PolicyCheck.Got = GPUevidence.UUID
			fail(&nvidiaResult.PolicyCheck, ar.VerifyPolicies,
				fmt.Errorf("UUID policy violation: %w", err))
			return result
		}
	}

	// --- Decode and split signed attestation report ------------------------
	rawEvidence, err := base64.StdEncoding.DecodeString(GPUevidence.SignedAttestationReport)
	if err != nil {
		result.Summary.Fail(ar.ParseEvidence, fmt.Errorf("failed to base64 decode attestation report: %w", err))
		return result
	}

	// The report is a GET_MEASUREMENTS request, the MEASUREMENTS response and a
	// trailing signature.
	signatureLen := archData.signatureLen
	evidenceLen := len(rawEvidence)
	if evidenceLen < SPDM_REQUEST_kRequestLength+signatureLen {
		result.Summary.Fail(ar.EvidenceLength,
			fmt.Errorf("evidence of %d bytes is shorter than the %d byte SPDM request plus %d byte signature",
				evidenceLen, SPDM_REQUEST_kRequestLength, signatureLen))
		return result
	}
	dataWoSignature := rawEvidence[:evidenceLen-signatureLen]
	signature := rawEvidence[evidenceLen-signatureLen:]

	// --- Parse device certificate chain ------------------------------------
	// Everything up to and including the signature check establishes that the report was
	// signed by a key the pinned device root vouches for, so all of it is recorded on
	// MeasurementSignatureCheck
	chainBytes, err := base64.StdEncoding.DecodeString(GPUevidence.Certificates)
	if err != nil {
		fail(&nvidiaResult.MeasurementSignatureCheck, ar.DecodeCertChain,
			fmt.Errorf("failed to base64 decode device cert chain: %w", err))
		return result
	}

	parsedChain, err := internal.ParseCertChain(chainBytes)
	if err != nil {
		fail(&nvidiaResult.MeasurementSignatureCheck, ar.ParseCert,
			fmt.Errorf("failed to parse device cert chain: %w", err))
		return result
	}

	// Anchor the chain before the signature is checked against its leaf.
	if err := anchorDeviceChain(parsedChain, nvidiaPolicy.DeviceCaFingerprints); err != nil {
		nvidiaResult.MeasurementSignatureCheck.ExpectedOneOf = nvidiaPolicy.DeviceCaFingerprints
		fail(&nvidiaResult.MeasurementSignatureCheck, ar.VerifyCertChain,
			fmt.Errorf("device certificate chain is not trusted: %w", err))
		return result
	}

	pubKey, ok := parsedChain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fail(&nvidiaResult.MeasurementSignatureCheck, ar.ExtractPubKey,
			errors.New("leaf certificate public key is not ECDSA"))
		return result
	}

	// --- Signature verification --------------------------------------------
	err = VerifyCertChainSignature(pubKey, signature, dataWoSignature)
	if err != nil {
		fail(&nvidiaResult.MeasurementSignatureCheck, ar.VerifySignature,
			fmt.Errorf("report signature verification failed: %w", err))
		return result
	}

	log.Debugf("Verifying signature of GPU evidence: SUCCESS")
	nvidiaResult.MeasurementSignatureCheck.Status = ar.StatusSuccess

	req, err := CreateSpdmMeasurementRequestMessage11(rawEvidence[:SPDM_REQUEST_kRequestLength])
	if err != nil {
		result.Summary.Fail(ar.ParseEvidence, fmt.Errorf("failed to parse SPDM request: %w", err))
		return result
	}

	// --- Parse SPDM response -----------------------------------------------
	rawSpdmResponse := rawEvidence[SPDM_REQUEST_kRequestLength:]
	spdmResponse, err := CreateSpdmMeasurementResponseMessage11(rawSpdmResponse, signatureLen)
	if err != nil {
		result.Summary.Fail(ar.ParseEvidence, fmt.Errorf("failed to parse SPDM response: %w", err))
		return result
	}

	nvdec0Status := GetSPDMOpaqueFieldOfType(spdmResponse, GpuOpaqueDataTypeNvdec0Status)
	if nvdec0Status == nil {
		result.Summary.Fail(ar.ParseEvidence,
			errors.New("failed to retrieve nvdec0 status field from SPDM response"))
		return result
	}
	nvdec0Enabled := nvdec0Status[0] != nvdec0StatusDisabled

	// Record the freshness check even when the policy tolerates a mismatch, so that
	// a relying party can see that the report was not bound to its nonce
	result.Freshness = verifyNonce(req.nonce[:], nonce)
	if result.Freshness.Status != ar.StatusSuccess {
		if nvidiaPolicy.EnforceNonce {
			result.Summary.Fail(ar.Freshness,
				errors.New("nonce mismatch and EnforceNonce is set, rejecting potential replay"))
			return result
		}
		log.Warn("Nonce mismatch detected, not enforced by policy")
	}

	// --- Version extraction ------------------------------------------------
	vbiosVersion, _ := spdmResponse.getVbiosVersion()
	driverVersion, _ := spdmResponse.getDriverVersion()

	// --- RIM retrieval and verification ------------------------------------
	requireOCSP := nvidiaPolicy.RequireOCSPForRIMs

	rimUnion, err := GetRIMUnionForVersions(collateral, driverVersion, vbiosVersion, requireOCSP,
		nvidiaPolicy.RimCaFingerprints)
	if err != nil {
		// Retrieval, signature and, if required, revocation of the RIMs are a single step,
		// so a failure of any of them is recorded on the signature check
		nvidiaResult.RIMSignatureCheck.ExpectedOneOf = nvidiaPolicy.RimCaFingerprints
		fail(&nvidiaResult.RIMSignatureCheck, ar.ParseCollateral,
			fmt.Errorf("failed to retrieve RIM union for driver %s and vbios %s: %w",
				driverVersion, vbiosVersion, err))
		return result
	}

	nvidiaResult.RIMSignatureCheck.Status = ar.StatusSuccess

	// Recency is only established when the RIM signing chain was checked against the OCSP
	// responses. Without the policy demanding it, nothing was checked, which is reported as
	// a warning rather than as a failure of a check that did not run
	if requireOCSP {
		nvidiaResult.RIMRecencyCheck.Status = ar.StatusSuccess
	} else {
		nvidiaResult.RIMRecencyCheck.Warn(ar.NotSpecified,
			errors.New("RIM revocation status not checked, RequireOCSPForRIMs is not set"))
	}

	// --- Measurement record parsing ----------------------------------------
	measurementRecord, err := ParseMeasurementRecord(spdmResponse.MeasurementRecordData)
	if err != nil {
		fail(&nvidiaResult.MeasurementRIMCheck, ar.ParseEvidence,
			fmt.Errorf("failed to parse measurement record: %w", err))
		return result
	}

	// Count active RIM pairs; the measurement record must cover at least that many.
	activePairCount := 0
	for i := range rimUnion.Pairs {
		if rimUnion.Pairs[i].Active {
			activePairCount++
		}
	}
	if len(measurementRecord) < activePairCount {
		nvidiaResult.MeasurementRIMCheck.Got = fmt.Sprintf("%d measurement record entries",
			len(measurementRecord))
		nvidiaResult.MeasurementRIMCheck.Expected = fmt.Sprintf("%d active RIM pairs",
			activePairCount)
		fail(&nvidiaResult.MeasurementRIMCheck, ar.MeasurementNoMatch,
			fmt.Errorf("measurement record has %d entries but RIM requires %d active pairs",
				len(measurementRecord), activePairCount))
		return result
	}

	for i := range rimUnion.Pairs {
		if i == nvdec0MeasurementIndex && !nvdec0Enabled {
			continue
		}
		if !rimUnion.Pairs[i].Active {
			continue
		}

		if i >= len(measurementRecord) {
			fail(&nvidiaResult.MeasurementRIMCheck, ar.MeasurementNoMatch,
				fmt.Errorf("active RIM pair at index %d has no corresponding measurement record entry", i))
			return result
		}

		measHex := hex.EncodeToString(measurementRecord[i].Value)
		if _, foundMatch := rimUnion.Pairs[i].HashMap[measHex]; !foundMatch {
			nvidiaResult.MeasurementRIMCheck.Got = measHex
			nvidiaResult.MeasurementRIMCheck.ExpectedOneOf = rimUnion.Pairs[i].Hashes
			fail(&nvidiaResult.MeasurementRIMCheck, ar.MeasurementNoMatch,
				fmt.Errorf("measurement record %d: no matching RIM hash found", i))
			return result
		}
	}

	nvidiaResult.MeasurementRIMCheck.Status = ar.StatusSuccess
	log.Debugf("Checking whether Measurements match RIMS: SUCCESS")

	// --- Device certificate and OCSP verification --------------------------
	err = VerifyDeviceCerts(collateral, parsedChain, GPUevidence.UUID,
		nvidiaPolicy.DeviceCaFingerprints)
	if err != nil {
		fail(&nvidiaResult.DeviceRecencyCheck, ar.VerifyCertChain,
			fmt.Errorf("verifying device certs failed: %w", err))
		return result
	}

	nvidiaResult.DeviceRecencyCheck.Status = ar.StatusSuccess
	log.Debugf("Verifying device certs with OCSP responses: SUCCESS")

	if nvidiaExtraSecPolicy != nil {
		if err := enforceExtraPolicy(GPUevidence.UnsignedMeasurements, nvidiaExtraSecPolicy); err != nil {
			fail(&nvidiaResult.PolicyCheck, ar.VerifyPolicies,
				fmt.Errorf("extra security policy violation: %w", err))
			return result
		}
	}

	// --- Version policy checks ---------------------------------------------

	// Both versions are checked before reporting, so that a report which violates both
	// minimums does not hide the second violation behind the first
	var policyErrs []error

	// An unset minimum means the version is not constrained. Comparing against
	// the empty string would fail to parse and reject every report, which would
	// make a policy that only sets, say, EnforceNonce unusable
	if nvidiaPolicy.DriverMinVersion != "" {
		driverCmp, err := compareVersions(driverVersion, nvidiaPolicy.DriverMinVersion)
		if err != nil {
			policyErrs = append(policyErrs,
				fmt.Errorf("failed to compare driver versions: %w", err))
		} else if driverCmp < 0 {
			policyErrs = append(policyErrs,
				fmt.Errorf("driver version %q is below minimum required %q",
					driverVersion, nvidiaPolicy.DriverMinVersion))
		}
	}

	if nvidiaPolicy.VbiosMinVersion != "" {
		vbiosCmp, err := compareVersions(vbiosVersion, nvidiaPolicy.VbiosMinVersion)
		if err != nil {
			policyErrs = append(policyErrs,
				fmt.Errorf("failed to compare vbios versions: %w", err))
		} else if vbiosCmp < 0 {
			policyErrs = append(policyErrs,
				fmt.Errorf("vbios version %q is below minimum required %q",
					vbiosVersion, nvidiaPolicy.VbiosMinVersion))
		}
	}

	if len(policyErrs) > 0 {
		nvidiaResult.PolicyCheck.Got = fmt.Sprintf("driver %v, vbios %v", driverVersion, vbiosVersion)
		fail(&nvidiaResult.PolicyCheck, ar.VerifyPolicies, errors.Join(policyErrs...))
		return result
	}

	nvidiaResult.PolicyCheck.Status = ar.StatusSuccess
	result.Summary.Status = ar.StatusSuccess

	return result
}
