// Copyright (c) 2021 Fraunhofer AISEC
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
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"

	"time"
)

type PolicyEngineSelect uint32

const (
	PolicyEngineSelect_None    PolicyEngineSelect = 0
	PolicyEngineSelect_JS      PolicyEngineSelect = 1
	PolicyEngineSelect_DukTape PolicyEngineSelect = 2
)

type PolicyValidator interface {
	Validate(policies []byte, result *ar.VerificationResult) bool
}

var (
	log = logrus.WithField("service", "ar")

	policyEngines = map[PolicyEngineSelect]PolicyValidator{}
)

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificate. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the reference values and the compatibility of software artefacts.
func Verify(
	arRaw, nonce, casPem, policies []byte,
	peer string,
	polEng PolicyEngineSelect,
	metadatamap map[string][]byte,
	intelCache string,
) *ar.VerificationResult {

	if len(metadatamap) == 0 {
		log.Warnf("No metadata specified")
	}

	result := &ar.VerificationResult{
		Type:      "Verification Result",
		Prover:    "Unknown",
		Success:   true,
		CertLevel: 0,
	}

	cas, err := internal.ParseCertsPem(casPem)
	if err != nil {
		log.Tracef("Failed to parse specified CA certificate(s): %v", err)
		result.Success = false
		result.ErrorCode = ar.ParseCA
		return result
	}

	// Detect serialization format
	log.Tracef("Detecting serialization format of attestation report length %v", len(arRaw))
	s, err := ar.DetectSerialization(arRaw)
	if err != nil {
		log.Trace("Unable to detect AR serialization format")
		result.Success = false
		result.ErrorCode = ar.UnknownSerialization
		return result
	}

	// Verify and unpack attestation report
	report, tr, code := verifyAr(arRaw, cas, s)
	result.ReportSignature = tr.SignatureCheck
	if code != ar.NotSet {
		result.ErrorCode = code
		result.Success = false
		return result
	}

	// Verify and unpack metadata from attestation report
	devDescName, metadata, metaResults, ec, ok := verifyMetadata(cas, s, metadatamap)
	if !ok {
		result.Success = false
		result.ErrorCode = ec
	}
	result.Metadata = metaResults

	refVals, err := collectReferenceValues(metadata)
	if err != nil {
		log.Tracef("Failed to collect reference values: %v", err)
		result.Success = false
		result.ErrorCode = ar.RefValTypeNotSupported
	}

	hwAttest := false
	for _, m := range report.Measurements {

		switch mtype := m.Type; mtype {

		case "TPM Measurement":
			r, ok := verifyTpmMeasurements(m, nonce, cas, s, refVals["TPM Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SNP Measurement":
			r, ok := verifySnpMeasurements(m, nonce, refVals["SNP Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "TDX Measurement":
			r, ok := verifyTdxMeasurements(m, nonce, intelCache, refVals["TDX Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SGX Measurement":
			r, ok := verifySgxMeasurements(m, nonce, intelCache, refVals["SGX Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "IAS Measurement":
			r, ok := verifyIasMeasurements(m, nonce, cas, refVals["IAS Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SW Measurement":
			r, ok := verifySwMeasurements(m, nonce, cas, s, refVals["SW Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)

		default:
			log.Tracef("Unsupported measurement type '%v'", mtype)
			result.Success = false
			result.ErrorCode = ar.MeasurementTypeNotSupported
		}
	}

	// The lowest certification level of all manifests determines the certification
	// level for the device's software stack
	aggCertLevel := 0
	levels := make([]int, 0)
	for _, m := range metadata {
		if m.Type == "Device Description" || m.Type == "Company Description" {
			// Descriptions do not have a certification level
			continue
		}
		levels = append(levels, m.CertLevel)
	}
	if len(levels) > 0 {
		aggCertLevel = slices.Min(levels)
	}
	log.Tracef("Aggregated cert level: %v", aggCertLevel)
	// If no hardware trust anchor is present, the maximum certification level is 1
	// If there are reference values with a higher trust level present, the remote attestation
	// must fail
	if !hwAttest && aggCertLevel > 1 {
		log.Tracef("No hardware trust anchor measurements present but claimed certification level is %v, which requires a hardware trust anchor", aggCertLevel)
		result.ErrorCode = ar.InvalidCertLevel
		result.Success = false
	}
	result.CertLevel = aggCertLevel

	// Validate policies if specified
	result.PolicySuccess = true
	if policies != nil {
		p, ok := policyEngines[polEng]
		if !ok {
			log.Tracef("Internal error: policy engine %v not implemented", polEng)
			result.Success = false
			result.ErrorCode = ar.PolicyEngineNotImplemented
			result.PolicySuccess = false
		} else {
			ok = p.Validate(policies, result)
			if !ok {
				log.Trace("Custom policy validation failed")
				result.Success = false
				result.ErrorCode = ar.VerifyPolicies
				result.PolicySuccess = false
			}
		}
	} else {
		log.Tracef("No custom policies specified")
	}

	// Add additional information
	result.Prover = devDescName
	if result.Prover == "" {
		result.Prover = "Unknown"
	}
	result.Created = time.Now().Format(time.RFC3339Nano)

	if result.Success {
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover, result.Created)
	} else {
		log.Infof("FAILED: Verification for Prover %v (%v)", result.Prover, result.Created)
	}

	return result
}

func verifyAr(attestationReport []byte, cas []*x509.Certificate, s ar.Serializer,
) (*ar.AttestationReport, ar.MetadataResult, ar.ErrorCode) {

	report := ar.AttestationReport{}

	//Validate Attestation Report signature
	result, payload, ok := s.Verify(attestationReport, cas)
	if !ok {
		log.Trace("Validation of Attestation Report failed")
		return nil, result, ar.VerifyAR
	}

	err := s.Unmarshal(payload, &report)
	if err != nil {
		log.Tracef("Parsing of Attestation Report failed: %v", err)
		return nil, result, ar.ParseAR
	}

	return &report, result, ar.NotSet
}

func verifyMetadata(cas []*x509.Certificate, s ar.Serializer, metadatamap map[string][]byte,
) (string, map[string]ar.Metadata, ar.MetadataSummary, ar.ErrorCode, bool) {

	devDescName := ""
	metadata := map[string]ar.Metadata{}
	results := ar.MetadataSummary{}
	errCode := ar.NotSet
	success := true
	var err error

	for hash, meta := range metadatamap {

		result, payload, ok := s.Verify(meta, cas)
		if !ok {
			log.Tracef("Validation of metadata item %v failed", hash)
			success = false
			// Still unpack metadata item for validation-result diagnosis
			payload, err = s.GetPayload(meta)
			if err != nil {
				// Summary and error code have already been set in verify
				log.Tracef("Get unverified payload of metadata item %v failed: %v", hash, err)
			}
		}

		m := new(ar.Metadata)
		err := s.Unmarshal(payload, m)
		if err != nil {
			log.Tracef("Unpacking of metadata item %v failed: %v", hash, err)
			result.Summary.Success = false
			result.Summary.ErrorCode = ar.Parse
			success = false
		}

		result.MetaInfo = m.MetaInfo
		result.Description = m.Description
		result.Location = m.Location
		result.CertLevel = m.CertLevel
		result.Details = m.Details
		result.ValidityCheck = checkValidity(m.Validity)
		if !result.ValidityCheck.Success {
			log.Tracef("%v: %v expired (NotBefore: %v, NotAfter: %v)", m.Type, m.Name, m.Validity.NotBefore, m.Validity.NotAfter)
			result.Summary.Success = false
			success = false
		} else {
			log.Tracef("Checking validity of %v: %v successful", m.Type, m.Name)
		}

		metadata[m.Name] = *m

		switch m.Type {

		case "Device Description":
			devDescName = m.Name
			results.DevDescResult = result
		case "Company Description":
			results.CompDescResult = &result
		case "RTM Manifest":
			results.RtmResult = result
		case "OS Manifest":
			results.OsResult = result
		case "App Manifest":
			results.AppResults = append(results.AppResults, result)
		default:
			log.Tracef("Unknown manifest type %v", m.Type)
			success = false
			errCode = ar.UnknownMetadata
		}

	}

	// Check metadata compatibility and update device description result
	_, ok := metadata[devDescName]
	if !ok {
		log.Tracef("Device description not present")
		success = false
		errCode = ar.DeviceDescriptionNotPresent
	} else {
		r, ok := checkMetadataCompatibility(devDescName, metadata)
		if !ok {
			success = false
		}
		results.DevDescResult.Summary.Success = ok
		results.DevDescResult.DevDescResult = *r
	}

	return devDescName, metadata, results, errCode, success
}

func checkMetadataCompatibility(devDescName string, metadata map[string]ar.Metadata) (*ar.DevDescResult, bool) {

	DevDescResult := &ar.DevDescResult{
		CorrectRtm:         &ar.Result{},
		CorrectOs:          &ar.Result{},
		RtmOsCompatibility: &ar.Result{},
	}
	success := true

	// Fail silently as the error is already logged in the calling function
	deviceDescription, ok := metadata[devDescName]
	if !ok {
		return nil, false
	}

	// Check that the OS and RTM Manifest are specified in the Device Description
	if _, ok := metadata[deviceDescription.RtmManifest]; ok {
		DevDescResult.CorrectRtm.Success = true
	} else {
		log.Tracef("Device Description listed wrong RTM Manifest: %v", deviceDescription.RtmManifest)
		DevDescResult.CorrectRtm.Success = false
		DevDescResult.CorrectRtm.Expected = deviceDescription.RtmManifest
		success = false
	}
	if _, ok := metadata[deviceDescription.OsManifest]; ok {
		DevDescResult.CorrectOs.Success = true
	} else {
		log.Tracef("Device Description listed wrong OS Manifest: %v", deviceDescription.OsManifest)
		DevDescResult.CorrectOs.Success = false
		DevDescResult.CorrectOs.Expected = deviceDescription.OsManifest
		success = false
	}

	// Extract app manifest names
	appManifestNames := make([]string, 0)
	for _, m := range metadata {
		if m.Type == "App Description" {
			appManifestNames = append(appManifestNames, m.Name)
		}
	}

	// Check that every App Description has a corresponding App Manifest
	log.Tracef("Iterating app descriptions length %v", len(deviceDescription.AppDescriptions))
	for _, desc := range deviceDescription.AppDescriptions {

		_, ok := metadata[desc.AppManifest]
		if !ok {
			log.Tracef("No app manifest for app description: %v", desc.AppManifest)
		}

		r := ar.Result{
			Success:       ok,
			Got:           desc.AppManifest,
			ExpectedOneOf: appManifestNames,
		}
		DevDescResult.CorrectApps = append(DevDescResult.CorrectApps, r)

	}

	// Check that the Rtm Manifest is compatible with the OS Manifest
	if rtm, ok := metadata[deviceDescription.RtmManifest]; ok {
		if os, ok := metadata[deviceDescription.OsManifest]; ok {
			if contains(rtm.Name, os.BaseLayers) {
				DevDescResult.RtmOsCompatibility.Success = true
			} else {
				log.Tracef("OS Manifest %v is not compatible with RTM Manifest %v",
					rtm.Name, os.Name)
				DevDescResult.RtmOsCompatibility.Success = false
				DevDescResult.RtmOsCompatibility.ExpectedOneOf = os.BaseLayers
				DevDescResult.RtmOsCompatibility.Got = rtm.Name
				success = false
			}
		}
	}

	// Check that the OS Manifest is compatible with all App Manifests
	if os, ok := metadata[deviceDescription.OsManifest]; ok {
		for _, a := range metadata {
			if a.Type == "App Manifest" {
				r := ar.Result{
					Success:       true,
					ExpectedOneOf: a.BaseLayers,
					Got:           os.Name,
				}
				if !contains(os.Name, a.BaseLayers) {
					log.Tracef("App Manifest %v is not compatible with OS Manifest %v", a.Name, os.Name)
					r.Success = false
					success = false
				}
				DevDescResult.OsAppsCompatibility =
					append(DevDescResult.OsAppsCompatibility, r)
			}
		}
	}

	return DevDescResult, success
}

func checkValidity(val ar.Validity) ar.Result {
	result := ar.Result{}
	result.Success = true

	notBefore, err := time.Parse(time.RFC3339, val.NotBefore)
	if err != nil {
		log.Tracef("Failed to parse NotBefore time. Time.Parse returned %v", err)
		result.Success = false
		result.ErrorCode = ar.ParseTime
		return result
	}
	notAfter, err := time.Parse(time.RFC3339, val.NotAfter)
	if err != nil {
		log.Tracef("Failed to parse NotAfter time. Time.Parse returned %v", err)
		result.Success = false
		result.ErrorCode = ar.ParseTime
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		log.Trace("Validity check failed: Artifact is not valid yet")
		result.Success = false
		result.ErrorCode = ar.NotYetValid
	}

	if currentTime.After(notAfter) {
		log.Trace("Validity check failed: Artifact validity has expired")
		result.Success = false
		result.ErrorCode = ar.Expired
	}

	return result
}

func collectReferenceValues(metadata map[string]ar.Metadata) (map[string][]ar.ReferenceValue, error) {

	refmap := make(map[string][]ar.ReferenceValue)
	// Iterate over all manifests (iterator required)
	for i := range metadata {
		for _, r := range metadata[i].ReferenceValues {
			// Check reference value type
			if r.Type != "SNP Reference Value" &&
				r.Type != "SW Reference Value" &&
				r.Type != "TPM Reference Value" &&
				r.Type != "TDX Reference Value" &&
				r.Type != "SGX Reference Value" {
				return nil, fmt.Errorf("reference value of type %v is not supported", r.Type)
			}

			// Note: The indirection and iterator are required, otherwise the manifest reference
			// in the reference value would always point to the last element in the map
			m := metadata[i]
			// Add a reference to the corresponding manifest to each reference value
			r.SetManifest(&m)

			// Collect all reference values, depending on type, independent of the manifest
			refmap[r.Type] = append(refmap[r.Type], r)
		}
	}

	return refmap, nil
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) (ar.Result, bool) {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			log.Tracef("Found %v, length %v, values %v", oid, len(ext.Value), ext.Value)
			if len(ext.Value) != 3 && len(ext.Value) != 4 {
				log.Tracef("extension %v value unexpected length %v (expected 3 or 4)",
					oid, len(ext.Value))
				return ar.Result{Success: false, ErrorCode: ar.OidLength}, false
			}
			if ext.Value[0] != 0x2 {
				log.Tracef("extension %v value[0]: %v does not match expected value 2 (tag Integer)",
					oid, ext.Value[0])
				return ar.Result{Success: false, ErrorCode: ar.OidTag}, false
			}
			if ext.Value[1] == 0x1 {
				if ext.Value[2] != value {
					log.Tracef("extension %v value[2]: %v does not match expected value %v",
						oid, ext.Value[2], value)
					return ar.Result{
						Success:  false,
						Expected: fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
						Got:      strconv.FormatUint(uint64(ext.Value[2]), 10),
					}, false
				}
			} else if ext.Value[1] == 0x2 {
				// Due to openssl, the sign bit must remain zero for positive integers
				// even though this field is defined as unsigned int in the AMD spec
				// Thus, if the most significant bit is required, one byte of additional 0x00 padding is added
				if ext.Value[2] != 0x00 || ext.Value[3] != value {
					log.Tracef("extension %v value = %v%v does not match expected value  %v",
						oid, ext.Value[2], ext.Value[3], value)
					return ar.Result{
						Success:  false,
						Expected: fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
						Got:      strconv.FormatUint(uint64(ext.Value[3]), 10),
					}, false
				}
			} else {
				log.Tracef("extension %v value[1]: %v does not match expected value 1 or 2 (length of integer)",
					oid, ext.Value[1])
				return ar.Result{Success: false, ErrorCode: ar.OidLength}, false
			}
			return ar.Result{
				Success: true,
				Got:     fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
			}, true
		}
	}

	log.Tracef("extension %v not present in certificate", oid)
	return ar.Result{Success: false, ErrorCode: ar.OidNotPresent}, false
}

func checkExtensionBuf(cert *x509.Certificate, oid string, buf []byte) (ar.Result, bool) {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if cmp := bytes.Compare(ext.Value, buf); cmp != 0 {
				log.Tracef("extension %v value %v does not match expected value %v",
					oid, hex.EncodeToString(ext.Value), hex.EncodeToString(buf))
				return ar.Result{
					Success:  false,
					Expected: fmt.Sprintf("%v: %v", oidDesc(oid), hex.EncodeToString(buf)),
					Got:      hex.EncodeToString(ext.Value),
				}, false
			}
			return ar.Result{
				Success: true,
				Got:     fmt.Sprintf("%v: %v", oidDesc(oid), hex.EncodeToString(ext.Value)),
			}, true
		}
	}

	log.Tracef("extension %v not present in certificate", oid)
	return ar.Result{Success: false, ErrorCode: ar.OidNotPresent}, false
}

func getExtensionString(cert *x509.Certificate, oid string) (string, bool) {

	for _, ext := range cert.Extensions {
		if ext.Id.String() == oid {
			return string(ext.Value), true
		}
	}
	log.Tracef("extension %v: %v not present in certificate", oid, oidDesc(oid))
	return "", false
}

func contains(elem string, list []string) bool {
	for _, s := range list {
		if s == elem {
			return true
		}
	}
	return false
}

func extendSha256(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha256.Sum256(concat)
	ret := make([]byte, 32)
	copy(ret, h[:])
	return ret
}

func extendSha384(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha512.Sum384(concat)
	ret := make([]byte, 48)
	copy(ret, h[:])
	return ret
}
