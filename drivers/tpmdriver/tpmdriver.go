// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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

package tpmdriver

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-attestation/attest"
	"go.mozilla.org/pkcs7"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"

	expmaps "golang.org/x/exp/maps"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/ima"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// Tpm is a structure that implements the Measure method
// of the attestation report Measurer interface
type Tpm struct {
	*drivers.DriverConfig
	mu       sync.Mutex
	pcrs     []int
	tpm      *attest.TPM
	ak       *attest.AK
	ek       []attest.EK
	akChain  []*x509.Certificate
	ctrLog   bool
	endorser drivers.TpmEndorser
}

const (
	akchainFile = "tpm_ak_chain.pem"
	akFile      = "tpm_ak_encrypted.json"

	DEFAULT_BINARY_BIOS_MEASUREMENTS = "/sys/kernel/security/tpm0/binary_bios_measurements"

	tpmResourceManagerPath = "/dev/tpmrm0"
	tpmDevicePath          = "/dev/tpm0"
)

var log = logrus.WithField("service", "tpmdriver")

// Name returns the name of the driver
func (t *Tpm) Name() string {
	return "TPM driver"
}

// Init opens and initializes a TPM object, checks if provisioning is
// required and if so, creates and activates a new attestation key (AK)
func (t *Tpm) Init(c *drivers.DriverConfig) error {

	// Initial checks
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	if c.Endorsers == nil {
		return fmt.Errorf("missing endorsers provider")
	}
	endorser, ok := c.Endorsers.Tpm()
	if !ok {
		return fmt.Errorf("tpm endorser not configured")
	}
	t.endorser = endorser

	t.DriverConfig = c
	t.ctrLog = c.Ctr && strings.EqualFold(c.CtrDriver, "tpm")

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create local storage '%v': %v", c.StoragePath, err)
			}
		}
	}

	// Check if the TPM is provisioned. If provisioned, load the AK and IK key.
	// Otherwise perform credential activation with provisioning server and then load the keys
	provisioningRequired, err := IsTpmProvisioningRequired(c.StoragePath)
	if err != nil {
		return fmt.Errorf("failed to check if TPM is provisioned: %w", err)
	}

	err = t.OpenTpm()
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}

	// Determine if the system is an SRTM or DRTM system to include the
	// respective PCRs into the TPM quote
	err = t.setQuotePcrs()
	if err != nil {
		return fmt.Errorf("failed to determine TPM Quote PCRs: %w", err)
	}

	if provisioningRequired {

		log.Info("Provisioning TPM (might take a while)..")

		err = t.provision()
		if err != nil {
			return fmt.Errorf("failed to provision TPM: %w", err)
		}

		if c.StoragePath != "" {
			err = t.saveAk()
			if err != nil {
				return fmt.Errorf("failed to save TPM data: %w", err)
			}
		}

	} else {
		err = t.loadAk()
		if err != nil {
			return fmt.Errorf("failed to load TPM keys: %w", err)
		}
	}

	name, err := t.getAkQualifiedName()
	if err != nil {
		return fmt.Errorf("failed to get AK qualified name: %w", err)
	}
	log.Debugf("Using AK with qualified name: %v", hex.EncodeToString(name))

	return nil
}

func (t *Tpm) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debug("Collecting TPM evidence")

	if t == nil {
		return nil, fmt.Errorf("internal error: tpm object not initialized")
	}
	if len(t.pcrs) == 0 {
		return nil, fmt.Errorf("TPM measurement does not contain any PCRs")
	}

	quote, err := t.GetQuote(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM Measurement: %w", err)
	}

	log.Tracef("Quote: %x", quote.Quote)
	log.Tracef("Signature: %x", quote.Signature)

	evidences := []ar.Evidence{
		{
			Type:      ar.TYPE_EVIDENCE_TPM,
			Data:      quote.Quote,
			Signature: quote.Signature,
		},
	}

	return evidences, nil
}

func (t *Tpm) GetCollateral() ([]ar.Collateral, error) {

	artifacts := make([]ar.Artifact, 0)

	if t.MeasurementLogs {
		events, err := GetEventLogs(t.pcrs, t.ctrLog, t.CtrLog, t.HashAlg)
		if err != nil {
			return nil, fmt.Errorf("failed to get event logs: %w", err)
		}
		artifacts = append(artifacts, events...)
	} else {
		pcrs, err := t.GetPcrs()
		if err != nil {
			return nil, fmt.Errorf("failed to get prs: %w", err)
		}
		artifacts = append(artifacts, pcrs...)
	}

	// Just for logging
	for _, elem := range artifacts {
		for _, event := range elem.Events {
			for _, h := range event.Hashes {
				log.Tracef("PCR%v %v: %v=%x", elem.Index, elem.Type, h.Alg, h.Content)
			}
		}
	}

	collateral := []ar.Collateral{
		{
			Type:      ar.TYPE_EVIDENCE_TPM,
			Certs:     internal.WriteCertsDer(t.akChain),
			Artifacts: artifacts,
		},
	}

	return collateral, nil
}

func (t *Tpm) lock() error {
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	log.Trace("Trying to get lock for TPM")
	t.mu.Lock()
	log.Trace("Got lock for TPM")
	return nil
}

func (t *Tpm) unlock() error {
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	log.Trace("Releasing TPM Lock")
	t.mu.Unlock()
	log.Trace("Released TPM Lock")
	return nil
}

func (t *Tpm) UpdateCerts() error {
	var err error

	// Initial checks
	if t == nil {
		return errors.New("internal error: tpm object is nil")
	}

	log.Info("Updating tpm certificates")

	log.Debugf("Flushing current keys")
	t.ak.Close(t.tpm)

	log.Debugf("Provisioning new keys and certs")
	err = t.provision()
	if err != nil {
		return fmt.Errorf("failed to provision tpm driver: %w", err)
	}

	log.Warnf("AK public: %v", t.ak.Public())

	if t.StoragePath != "" {
		err = t.saveAk()
		if err != nil {
			return fmt.Errorf("failed to save azure credentials: %w", err)
		}
	}

	return nil
}

func (t *Tpm) GetAkPublic() []byte {
	return t.ak.AttestationParameters().Public
}

// IsTpmProvisioningRequired checks if the Storage Root Key (SRK) is persisted
// at 0x810000001 and the encrypted AK blob is present, which is used as an
// indicator that the TPM is provisioned and the AK can directly be loaded.
// This function uses the low-level go-tpm library directly as go-attestation
// does not provide such a functionality.
func IsTpmProvisioningRequired(storagePath string) (bool, error) {

	// Stateless operation always requires provisioning
	if storagePath == "" {
		log.Info("TPM Credential Activation REQUIRED (no storage path)")
		return true, nil
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(storagePath, akchainFile)); err != nil {
		log.Info("TPM Credential Activation REQUIRED (no AK cert chain)")
		return true, nil
	}
	if _, err := os.Stat(path.Join(storagePath, akFile)); err != nil {
		log.Info("TPM Credential Activation REQUIRED (no AK)")
		return true, nil
	}

	// If the AK is not persisted in the TPM, we need to provision
	addr, err := GetTpmDevicePath()
	if err != nil {
		return true, fmt.Errorf("failed to find TPM device: %w", err)
	}
	rwc, err := tpm2.OpenTPM(addr)
	if err != nil {
		return true, fmt.Errorf("failed to open TPM%v: %w", addr, err)
	}
	defer rwc.Close()
	srkHandle := tpmutil.Handle(0x81000001)
	_, _, _, err = tpm2.ReadPublic(rwc, srkHandle)
	if err == nil {
		log.Info("TPM Provisioning (Credential Activation) NOT REQUIRED")
		return false, nil
	}
	log.Info("TPM Provisioning (Credential Activation) REQUIRED")

	return true, nil
}

func GetTpmDevicePath() (string, error) {
	if _, err := os.Stat(tpmResourceManagerPath); err == nil {
		return tpmResourceManagerPath, nil
	} else if _, err := os.Stat(tpmDevicePath); err == nil {
		return tpmDevicePath, nil
	} else {
		return "", errors.New("failed to find TPM device in /dev")
	}
}

// OpenTpm opens the TPM and stores the handle internally
func (t *Tpm) OpenTpm() error {
	log.Debug("Opening TPM")

	if t.tpm != nil {
		return fmt.Errorf("failed to open TPM - already open")
	}

	var err error
	config := &attest.OpenConfig{}
	t.tpm, err = attest.OpenTPM(config)
	if err != nil {
		t.tpm = nil
		return fmt.Errorf("failed to open TPM %w", err)
	}

	return nil
}

// CloseTpm closes the TPM
func (t *Tpm) CloseTpm() error {
	if t.tpm == nil {
		return fmt.Errorf("failed to close TPM - TPM is not openend")
	}
	t.tpm.Close()
	t.tpm = nil
	return nil
}

// GetTpmInfo retrieves general TPM infos
func (t *Tpm) GetTpmInfo() (*attest.TPMInfo, error) {

	if t.tpm == nil {
		return nil, fmt.Errorf("failed to Get TPM info - TPM is not openend")
	}

	tpmInfo, err := t.tpm.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM info - %w", err)
	}

	log.Tracef("VendorInfo          : %v", tpmInfo.VendorInfo)
	log.Tracef("FirmwareVersionMajor: %v", tpmInfo.FirmwareVersionMajor)
	log.Tracef("FirmwareVersionMinor: %v", tpmInfo.FirmwareVersionMinor)
	log.Tracef("Interface           : %v", tpmInfo.Interface)
	log.Tracef("Manufacturer        : %v", tpmInfo.Manufacturer.String())

	return tpmInfo, nil
}

// getAkQualifiedName gets the Attestation Key Qualified Name. According to
// Trusted Platform Module Library Part 1: Architecture:
//
//	Name = nameAlg || HASH (TPMS_NV_PUBLIC)
//	QName = HASH(QName_parent || Name)
func (t *Tpm) getAkQualifiedName() ([]byte, error) {

	if t.tpm == nil {
		return nil, errors.New("failed to get AK Qualified Name: TPM is not opened")
	}
	if t.ak == nil {
		return nil, errors.New("failed to get AK Qualified Name: AK does not exist")
	}

	// This is a TPMT_PUBLIC structure
	pub := t.ak.AttestationParameters().Public

	// TPMT_PUBLIC Contains algorithm used for hashing the public area to get
	// the name (nameAlg)
	tpm2Pub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to Decode AK Public: %w", err)
	}

	// Name of object is nameAlg || Digest(TPMT_PUBLIC)
	alg := make([]byte, 2)
	binary.BigEndian.PutUint16(alg, uint16(tpm2Pub.NameAlg))

	hashAlg, err := internal.Tpm2ToCryptoHash(tpm2Pub.NameAlg)
	if err != nil {
		return nil, err
	}

	digestPub, err := internal.Hash(hashAlg, pub)
	if err != nil {
		return nil, fmt.Errorf("unsupported tpm alg 0x%x", tpm2Pub.NameAlg)
	}

	name := append(alg, digestPub[:]...)

	// TPMS_CREATION_DATA contains parentQualifiedName
	createData := t.ak.AttestationParameters().CreateData
	tpm2CreateData, err := tpm2.DecodeCreationData(createData)
	if err != nil {
		return nil, fmt.Errorf("failed to Decode Creation Data: %w", err)
	}

	parentAlg := make([]byte, 2)
	binary.BigEndian.PutUint16(parentAlg, uint16(tpm2CreateData.ParentNameAlg))
	parentQualifiedName := append(parentAlg, tpm2CreateData.ParentQualifiedName.Digest.Value...)

	// QN_AK := H_AK(QN_Parent || NAME_AK)
	buf := append(parentQualifiedName[:], name[:]...)
	qualifiedNameDigest, err := internal.Hash(hashAlg, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to hash qualified name: %w", err)
	}
	qualifiedName := append(alg, qualifiedNameDigest[:]...)

	log.Debugf("AK Name: %v", hex.EncodeToString(name[:]))
	log.Debugf("AK Qualified Name: %v", hex.EncodeToString(qualifiedName[:]))

	return qualifiedName, nil
}

// GetQuote retrieves the Quote over the relevant PCRs
func (t *Tpm) GetQuote(nonce []byte) (*attest.Quote, error) {

	if t.tpm == nil {
		return nil, fmt.Errorf("TPM is not opened")
	}
	if t.ak == nil {
		return nil, fmt.Errorf("AK does not exist")
	}

	// Only one instance can have access to the tpm at the same time
	t.lock()
	defer t.unlock()

	hashAlg, err := internal.CryptoToAttestHash(t.HashAlg)
	if err != nil {
		return nil, err
	}

	log.Debugf("Collecting TPM Quote with hash %v for PCRs %v", t.HashAlg.String(), t.pcrs)

	// Retrieve quote and store quote data and signature in TPM measurement object
	quote, err := t.ak.QuotePCRs(t.tpm, nonce, hashAlg, t.pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM quote - %w", err)
	}
	log.Debug("Finished getting Quote from TPM")

	return quote, nil
}

func (t *Tpm) GetPcrs() ([]ar.Artifact, error) {
	// Only one instance can have access to the tpm at
	// the same time
	t.lock()
	defer t.unlock()

	hashAlg, err := internal.CryptoToAttestHash(t.HashAlg)
	if err != nil {
		return nil, err
	}

	pcrs, err := t.tpm.PCRs(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM PCRs: %w", err)
	}
	log.Debug("Finished reading PCRs from TPM")

	// Collect artifacts into map
	artifactmap := map[int]ar.Artifact{}
	for _, pcr := range pcrs {
		artifactmap[pcr.Index] = ar.Artifact{
			Type:  ar.TYPE_PCR_SUMMARY,
			Index: pcr.Index,
			Events: []ar.Component{
				{
					Hashes: []ar.ReferenceHash{
						{
							Alg:     pcr.DigestAlg.String(),
							Content: pcr.Digest,
						},
					},
				},
			},
		}
	}

	// Only return specified PCR artifacts
	artifacts := make([]ar.Artifact, 0, len(t.pcrs))
	for _, pcr := range t.pcrs {
		artifact, ok := artifactmap[pcr]
		if !ok {
			return nil, fmt.Errorf("internal error: PCR%v not present", pcr)
		}
		artifacts = append(artifacts, artifact)
	}

	// Sort artifacts list with ascending PCR index
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Index < artifacts[j].Index
	})

	return artifacts, nil
}

func GetEventLogs(pcrs []int, ctrLog bool, ctrLogFile string, alg crypto.Hash) ([]ar.Artifact, error) {

	log.Debugf("Collecting event logs for PCRs %v", pcrs)

	artifactmap, err := GetBiosArtifacts(DEFAULT_BINARY_BIOS_MEASUREMENTS,
		ar.TYPE_EVIDENCE_TPM, false, []crypto.Hash{alg})
	if err != nil {
		return nil, fmt.Errorf("failed to get binary bios measurements: %w", err)
	}

	runtimeMeasurements, err := ima.GetImaArtifacts(ima.DEFAULT_BINARY_RUNTIME_MEASUREMENTS)
	if err != nil {
		return nil, fmt.Errorf("failed to get ima runtime measurements: %w", err)
	}
	maps.Copy(artifactmap, runtimeMeasurements)

	if ctrLog {
		containerMeasurement, err := GetContainerArtifacts(ctrLogFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get container runtime measurements: %w", err)
		}
		artifactmap[containerMeasurement.Index] = *containerMeasurement
	}

	// Add artifacts for PCRs with no events. This is required to reconstruct the aggregated
	// quote PCR value during verification
	for _, index := range pcrs {
		if _, ok := artifactmap[index]; !ok {
			artifactmap[index] = ar.Artifact{
				Type:  ar.TYPE_PCR_EVENTLOG,
				Index: index,
			}
		}
	}

	// Remove artifacts whose indices are configured not to be present in the attestation
	pcrSet := make(map[int]struct{}, len(pcrs))
	for _, p := range pcrs {
		pcrSet[p] = struct{}{}
	}
	for idx := range artifactmap {
		if _, ok := pcrSet[idx]; !ok {
			delete(artifactmap, idx)
		}
	}

	// Get sorted artifacts list with ascending PCR index
	artifacts := expmaps.Values(artifactmap)
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Index < artifacts[j].Index
	})

	return artifacts, nil
}

func GetContainerArtifacts(path string) (*ar.Artifact, error) {

	log.Debugf("Reading container measurements")
	if _, err := os.Stat(path); err != nil {
		log.Trace("No container measurements to read")
		return nil, nil
	}

	// If CMC container measurements are used, add the list of executed containers
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read container measurements: %w", err)
	}

	s, err := ar.DetectSerialization(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect atls response serializationt: %v", err)
	}

	var eventlog *ar.Artifact
	err = s.Unmarshal(data, eventlog)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal measurement list: %w", err)
	}

	log.Debugf("Adding %v container events to PCR%v artifact", len(eventlog.Events), eventlog.Index)

	return eventlog, nil
}

func (t *Tpm) provision() error {
	var err error

	log.Debug("Performing TPM credential activation..")

	if t.tpm == nil {
		return errors.New("TPM is not openend")
	}

	t.ek, t.ak, err = createKeys(t.tpm, t.KeyAlg)
	if err != nil {
		return fmt.Errorf("activate credential failed: createKeys returned %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := t.endorser.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Retrieve and check FQDN (After the initial provisioning, we do not allow changing the FQDN)
	fqdn, err := internal.Fqdn()
	if err != nil {
		return fmt.Errorf("failed to get FQDN: %v", err)
	}

	akCert, err := t.provisionAk(fqdn)
	if err != nil {
		return fmt.Errorf("failed to provision AK cert chain: %w", err)
	}
	t.akChain = append([]*x509.Certificate{akCert}, caCerts...)

	return nil
}

func (t *Tpm) provisionAk(fqdn string) (*x509.Certificate, error) {

	log.Debug("Provisioning AK certificate..")

	// Retrieve TPM information
	tpmInfo, err := t.GetTpmInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TPM Info: %w", err)
	}

	// Encode EK public key
	ekPub, err := x509.MarshalPKIXPublicKey(t.ek[0].Public)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EK public key: %w", err)
	}
	var ekRaw []byte
	if t.ek[0].Certificate != nil {
		log.Debugf("Using EK %v", t.ek[0].Certificate.Subject.CommonName)
		ekRaw = t.ek[0].Certificate.Raw
	} else if t.ek[0].CertificateURL != "" {
		log.Debugf("Using EK URL %q", t.ek[0].CertificateURL)
		ekRaw = nil
	}

	// Create AK CSR and perform EST enrollment with TPM credential activation
	akCsr, err := t.createAkCsr(fqdn + " TPM AK")
	if err != nil {
		return nil, fmt.Errorf("failed to create AK CSR: %w", err)
	}

	log.Debugf("Performing AK TPM activate credential enroll for CN=%v", akCsr.Subject.CommonName)
	encCredential, encSecret, pkcs7Cert, err := t.endorser.TpmActivateEnroll(
		tpmInfo.Manufacturer.String(), t.ek[0].CertificateURL,
		tpmInfo.FirmwareVersionMajor, tpmInfo.FirmwareVersionMinor,
		akCsr,
		t.ak.AttestationParameters(),
		ekPub, ekRaw,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll AK: %w", err)
	}

	log.Debugf("Performing credential activation")
	secret, err := ActivateCredential(t.tpm, t.ak, encCredential, encSecret)
	if err != nil {
		return nil, fmt.Errorf("request activate credential failed: %w", err)
	}

	encryptedCert, err := pkcs7.Parse(pkcs7Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7 CMS EnvelopedData: %w", err)
	}

	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	certDer, err := encryptedCert.DecryptUsingPSK(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PKCS7 encrypted cert: %w", err)
	}

	akCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Debugf("Provisioned new AK Cert: %v", akCert.Subject.CommonName)

	return akCert, nil
}

func (t *Tpm) saveAk() error {

	// Store the encrypted AK blob on disk
	akBytes, err := t.ak.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal AK returned %w", err)
	}
	akPath := path.Join(t.StoragePath, akFile)
	if err := os.WriteFile(akPath, akBytes, 0600); err != nil {
		return fmt.Errorf("failed to write file %v: %w", akPath, err)
	}

	// Store the AK chain on disk
	akchainPem := make([]byte, 0)
	for _, cert := range t.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(t.StoragePath, akchainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(t.StoragePath, akchainFile), err)
	}

	return nil
}

func (t *Tpm) loadAk() error {

	if t.tpm == nil {
		return errors.New("tpm is not opened")
	}

	// Load encrypted AK into TPM
	akPath := path.Join(t.StoragePath, akFile)
	akBytes, err := os.ReadFile(akPath)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %w", akPath, err)
	}
	t.ak, err = t.tpm.LoadAK(akBytes)
	if err != nil {
		return fmt.Errorf("LoadAK failed: %w", err)
	}
	log.Debug("Loaded AK")

	// Load AK chain
	data, err := os.ReadFile(path.Join(t.StoragePath, akchainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", t.StoragePath, err)
	}
	t.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(t.akChain))

	return nil
}

func createKeys(tpm *attest.TPM, keyAlg string) ([]attest.EK, *attest.AK, error) {

	log.Debug("Loading EKs")

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load EKs - %w", err)
	}
	log.Debugf("Found %v EK(s)", len(eks))

	log.Debugf("Creating new AK with algorithm %v", keyAlg)
	akConfig := &attest.AKConfig{}
	switch keyAlg {
	case "EC256":
		akConfig.Algorithm = attest.ECDSA
	case "RSA2048":
		akConfig.Algorithm = attest.RSA
	default:
		return nil, nil, fmt.Errorf("unsupported TPM AK key algorithm: %v", keyAlg)
	}

	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new AK - %w", err)
	}

	return eks, ak, nil
}

func ActivateCredential(
	tpm *attest.TPM, ak *attest.AK,
	activationCredential, activationSecret []byte,
) ([]byte, error) {

	if activationCredential == nil {
		return nil, errors.New("did not receive encrypted credential from server")
	}
	if activationSecret == nil {
		return nil, errors.New("did not receive encrypted secret from server")
	}

	encryptedCredential := attest.EncryptedCredential{
		Credential: activationCredential,
		Secret:     activationSecret,
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredential)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed: %w", err)
	}

	return secret, nil
}

func (t *Tpm) setQuotePcrs() error {

	if t.tpm == nil {
		return fmt.Errorf("TPM is not opened")
	}

	// Read and Store PCRs into TPM Measurement structure. Lock this access, as only
	// one instance can have write access at the same time
	t.lock()
	defer t.unlock()

	hashAlg, err := internal.CryptoToAttestHash(t.HashAlg)
	if err != nil {
		return fmt.Errorf("failed to convert hash: %w", err)
	}

	log.Debug("Retrieving PCRs")
	pcrValues, err := t.tpm.PCRs(hashAlg)
	if err != nil {
		return fmt.Errorf("failed to get TPM PCRs: %w", err)
	}

	// Assume an SRTM system by default and quote the static PCRs
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}

	// Check if the system is a DRTM system
	for _, pcr := range pcrValues {
		if pcr.Index == 17 {
			cmp := make([]byte, pcr.DigestAlg.Size())
			for i := range cmp {
				cmp[i] = 0xff
			}

			// If PCR17 recorded measurements, this means the system is a DRTM systen,
			// so the dynamic PCRs must be quoted
			if !bytes.Equal(pcr.Digest, cmp) {
				pcrs = []int{17, 18, 19, 20, 21, 22}
			}
		}
	}

	t.pcrs = internal.FilterInts(pcrs, t.ExcludePcrs)

	log.Debugf("Using PCRs: %v", t.pcrs)

	return nil
}

// This function calls the modified version of x509.CreateCertificateRequest which does not
// perform hashing and can therefore be used to create CSRs for restricted tpm keys
func (t *Tpm) createAkCsr(cn string) (*x509.CertificateRequest, error) {

	log.Debugf("Creating AK CSR..")

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	// NOTE does not call x509.CreateCertificateRequest but instead a local
	// modified version
	der, err := CreateCertificateRequest(rand.Reader, &tmpl, t.ak, t.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %w", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %w", err)
	}

	return csr, nil
}
