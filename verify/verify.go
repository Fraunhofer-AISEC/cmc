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

package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
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
	Validate(policies []byte, result ar.VerificationResult) bool
}

var (
	log = logrus.WithField("service", "ar")

	policyEngines = map[PolicyEngineSelect]PolicyValidator{}
)

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificate. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the reference values and the compatibility of software artefacts.
func Verify(arRaw, nonce, casPem []byte, policies []byte, polEng PolicyEngineSelect, intelCache string) ar.VerificationResult {
	result := ar.VerificationResult{
		Type:        "Verification Result",
		Success:     true,
		SwCertLevel: 0}

	cas, err := internal.ParseCertsPem(casPem)
	if err != nil {
		log.Tracef("Failed to parse specified CA certificate(s): %v", err)
		result.Success = false
		result.ErrorCode = ar.ParseCA
		return result
	}

	// Detect serialization format
	var s ar.Serializer
	if json.Valid(arRaw) {
		log.Trace("Detected JSON serialization")
		s = ar.JsonSerializer{}
	} else if err := cbor.Valid(arRaw); err == nil {
		log.Trace("Detected CBOR serialization")
		s = ar.CborSerializer{}
	} else {
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
	metadata, mr, ok := verifyMetadata(report, cas, s)
	if !ok {
		result.Success = false
	}
	result.MetadataResult = *mr

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
			r, ok := verifyTpmMeasurements(m, nonce, cas, refVals["TPM Reference Value"])
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

	// The lowest certification level of all components determines the certification
	// level for the device's software stack
	levels := make([]int, 0)
	levels = append(levels, metadata.RtmManifest.CertificationLevel)
	levels = append(levels, metadata.OsManifest.CertificationLevel)
	for _, app := range metadata.AppManifests {
		levels = append(levels, app.CertificationLevel)
	}
	aggCertLevel := levels[0]
	for _, l := range levels {
		if l < aggCertLevel {
			aggCertLevel = l
		}
	}
	// If no hardware trust anchor is present, the maximum certification level is 1
	// If there are reference values with a higher trust level present, the remote attestation
	// must fail
	if !hwAttest && aggCertLevel > 1 {
		log.Tracef("No hardware trust anchor measurements present but claimed certification level is %v, which requires a hardware trust anchor", aggCertLevel)
		result.ErrorCode = ar.InvalidCertificationLevel
		result.Success = false
	}
	result.SwCertLevel = aggCertLevel

	// Verify the compatibility of the attestation report through verifying the
	// compatibility of all components

	// Check that the OS and RTM Manifest are specified in the Device Description
	if metadata.DeviceDescription.RtmManifest == metadata.RtmManifest.Name {
		result.DevDescResult.CorrectRtm.Success = true
	} else {
		log.Tracef("Device Description listed wrong RTM Manifest: %v vs. %v",
			metadata.DeviceDescription.RtmManifest, metadata.RtmManifest.Name)
		result.DevDescResult.CorrectRtm.Success = false
		result.DevDescResult.CorrectRtm.Expected = metadata.DeviceDescription.RtmManifest
		result.DevDescResult.CorrectRtm.Got = metadata.RtmManifest.Name
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}
	if metadata.DeviceDescription.OsManifest == metadata.OsManifest.Name {
		result.DevDescResult.CorrectOs.Success = true
	} else {
		log.Tracef("Device Description listed wrong OS Manifest: %v vs. %v",
			metadata.DeviceDescription.OsManifest, metadata.OsManifest.Name)
		result.DevDescResult.CorrectOs.Success = false
		result.DevDescResult.CorrectOs.Expected = metadata.DeviceDescription.OsManifest
		result.DevDescResult.CorrectOs.Got = metadata.OsManifest.Name
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}

	// Extract app description names
	appDescriptions := make([]string, 0)
	for _, a := range metadata.DeviceDescription.AppDescriptions {
		appDescriptions = append(appDescriptions, a.AppManifest)
	}
	// Extract app manifest names
	appManifestNames := make([]string, 0)
	for _, a := range metadata.AppManifests {
		appManifestNames = append(appManifestNames, a.Name)
	}

	// Check that every AppManifest has a corresponding AppDescription
	log.Tracef("Iterating app manifests length %v", len(metadata.AppManifests))
	for _, a := range metadata.AppManifests {
		r := ar.Result{
			Success:       true,
			ExpectedOneOf: appDescriptions,
			Got:           a.Name,
		}
		if !contains(a.Name, appDescriptions) {
			log.Tracef("Device Description does not list the following App Manifest: %v", a.Name)
			r.Success = false
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
		result.DevDescResult.CorrectApps = append(result.DevDescResult.CorrectApps, r)
	}

	// Check that every App Description has a corresponding App Manifest
	log.Tracef("Iterating app descriptions length %v", len(metadata.DeviceDescription.AppDescriptions))
	for _, desc := range metadata.DeviceDescription.AppDescriptions {
		found := false
		for _, manifest := range metadata.AppManifests {
			if desc.AppManifest == manifest.Name {
				found = true
			}
		}
		if !found {
			log.Tracef("No app manifest for app description: %v", desc.AppManifest)
			r := ar.Result{
				Success:       false,
				Got:           desc.AppManifest,
				ExpectedOneOf: appManifestNames,
			}
			result.DevDescResult.CorrectApps = append(result.DevDescResult.CorrectApps, r)
			result.Success = false
		}
	}

	// Check that the Rtm Manifest is compatible with the OS Manifest
	if contains(metadata.RtmManifest.Name, metadata.OsManifest.Rtms) {
		result.DevDescResult.RtmOsCompatibility.Success = true
	} else {
		log.Tracef("RTM Manifest %v is not compatible with OS Manifest %v",
			metadata.RtmManifest.Name, metadata.OsManifest.Name)
		result.DevDescResult.RtmOsCompatibility.Success = false
		result.DevDescResult.RtmOsCompatibility.ExpectedOneOf = metadata.OsManifest.Rtms
		result.DevDescResult.RtmOsCompatibility.Got = metadata.RtmManifest.Name
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}

	// Check that the OS Manifest is compatible with all App Manifests
	for _, a := range metadata.AppManifests {
		r := ar.Result{
			Success:       true,
			ExpectedOneOf: a.Oss,
			Got:           metadata.OsManifest.Name,
		}
		if !contains(metadata.OsManifest.Name, a.Oss) {
			log.Tracef("OS Manifest %v is not compatible with App Manifest %v", metadata.OsManifest.Name, a.Name)
			r.Success = false
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
		result.DevDescResult.OsAppsCompatibility =
			append(result.DevDescResult.OsAppsCompatibility, r)
	}

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
	result.Prover = metadata.DeviceDescription.Name
	if result.Prover == "" {
		result.Prover = "Unknown"
	}
	result.Created = time.Now().Format(time.RFC3339)

	if result.Success {
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover, result.Created)
	} else {
		log.Infof("FAILED: Verification for Prover %v (%v)", result.Prover, result.Created)
	}

	return result
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

func verifyAr(attestationReport []byte, cas []*x509.Certificate, s ar.Serializer,
) (*ar.AttestationReport, ar.TokenResult, ar.ErrorCode) {

	report := ar.AttestationReport{}

	//Validate Attestation Report signature
	result, payload, ok := s.VerifyToken(attestationReport, cas)
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

func verifyMetadata(report *ar.AttestationReport, cas []*x509.Certificate, s ar.Serializer,
) (*ar.Metadata, *ar.MetadataResult, bool) {

	metadata := &ar.Metadata{}
	result := &ar.MetadataResult{}
	success := true

	// Validate and unpack Rtm Manifest
	tokenRes, payload, ok := s.VerifyToken(report.RtmManifest, cas)
	result.RtmResult.Summary = tokenRes.Summary
	result.RtmResult.SignatureCheck = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of RTM Manifest failed")
		success = false
	} else {
		err := s.Unmarshal(payload, &metadata.RtmManifest)
		if err != nil {
			log.Tracef("Unpacking of RTM Manifest failed: %v", err)
			result.RtmResult.Summary.Success = false
			result.RtmResult.Summary.ErrorCode = ar.ParseRTMManifest
			success = false
		} else {
			result.RtmResult.MetaInfo = metadata.RtmManifest.MetaInfo
			result.RtmResult.ValidityCheck = checkValidity(metadata.RtmManifest.Validity)
			result.RtmResult.Details = metadata.RtmManifest.Details
			if !result.RtmResult.ValidityCheck.Success {
				result.RtmResult.Summary.Success = false
				success = false
			}
		}
	}

	// Validate and unpack OS Manifest
	tokenRes, payload, ok = s.VerifyToken(report.OsManifest, cas)
	result.OsResult.Summary = tokenRes.Summary
	result.OsResult.SignatureCheck = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of OS Manifest failed")
		success = false
	} else {
		err := s.Unmarshal(payload, &metadata.OsManifest)
		if err != nil {
			log.Tracef("Unpacking of OS Manifest failed: %v", err)
			result.OsResult.Summary.Success = false
			result.OsResult.Summary.ErrorCode = ar.ParseOSManifest
			success = false
		} else {
			result.OsResult.MetaInfo = metadata.OsManifest.MetaInfo
			result.OsResult.ValidityCheck = checkValidity(metadata.OsManifest.Validity)
			result.OsResult.Details = metadata.OsManifest.Details
			if !result.OsResult.ValidityCheck.Success {
				result.OsResult.Summary.Success = false
				success = false
			}
		}
	}

	// Validate and unpack App Manifests
	for i, amSigned := range report.AppManifests {
		result.AppResults = append(result.AppResults, ar.ManifestResult{})

		tokenRes, payload, ok = s.VerifyToken(amSigned, cas)
		result.AppResults[i].Summary = tokenRes.Summary
		result.AppResults[i].SignatureCheck = tokenRes.SignatureCheck
		if !ok {
			log.Trace("Validation of App Manifest failed")
			success = false
		} else {
			var am ar.AppManifest
			err := s.Unmarshal(payload, &am)
			if err != nil {
				log.Tracef("Unpacking of App Manifest failed: %v", err)
				result.AppResults[i].Summary.Success = false
				result.AppResults[i].Summary.ErrorCode = ar.Parse
				success = false
			} else {
				metadata.AppManifests = append(metadata.AppManifests, am)
				result.AppResults[i].MetaInfo = am.MetaInfo
				result.AppResults[i].ValidityCheck = checkValidity(am.Validity)
				if !result.AppResults[i].ValidityCheck.Success {
					log.Tracef("App Manifest %v validity check failed", am.Name)
					result.AppResults[i].Summary.Success = false
					success = false

				}
			}
		}
	}

	// Validate and unpack Company Description if present
	if report.CompanyDescription != nil {
		tokenRes, payload, ok = s.VerifyToken(report.CompanyDescription, cas)
		result.CompDescResult = &ar.CompDescResult{}
		result.CompDescResult.Summary = tokenRes.Summary
		result.CompDescResult.SignatureCheck = tokenRes.SignatureCheck
		if !ok {
			log.Trace("Validation of Company Description Signatures failed")
			success = false
		} else {
			err := s.Unmarshal(payload, &metadata.CompanyDescription)
			if err != nil {
				log.Tracef("Unpacking of Company Description failed: %v", err)
				result.CompDescResult.Summary.Success = false
				result.CompDescResult.Summary.ErrorCode = ar.Parse
				success = false
			} else {
				result.CompDescResult.MetaInfo = metadata.CompanyDescription.MetaInfo
				result.CompDescResult.CompCertLevel = metadata.CompanyDescription.CertificationLevel

				result.CompDescResult.ValidityCheck = checkValidity(metadata.CompanyDescription.Validity)
				if !result.CompDescResult.ValidityCheck.Success {
					log.Trace("Company Description invalid")
					result.CompDescResult.Summary.Success = false
					success = false
				}
			}
		}
	}

	// Validate and unpack Device Description
	tokenRes, payload, ok = s.VerifyToken(report.DeviceDescription, cas)
	result.DevDescResult.Summary = tokenRes.Summary
	result.DevDescResult.SignatureCheck = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of Device Description failed")
		success = false
	} else {
		err := s.Unmarshal(payload, &metadata.DeviceDescription)
		if err != nil {
			log.Tracef("Unpacking of Device Description failed: %v", err)
			result.DevDescResult.Summary.Success = false
			result.DevDescResult.Summary.ErrorCode = ar.Parse
			success = false
		} else {
			result.DevDescResult.MetaInfo = metadata.DeviceDescription.MetaInfo
			result.DevDescResult.Description = metadata.DeviceDescription.Description
			result.DevDescResult.Location = metadata.DeviceDescription.Location
		}
		for _, appDesc := range metadata.DeviceDescription.AppDescriptions {
			appResult := ar.AppDescResult{
				MetaInfo:    appDesc.MetaInfo,
				AppManifest: appDesc.AppManifest,
				External:    appDesc.External,
				Environment: appDesc.Environment,
			}
			result.DevDescResult.AppResults = append(result.DevDescResult.AppResults,
				appResult)
		}
	}

	return metadata, result, success
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

func collectReferenceValues(metadata *ar.Metadata) (map[string][]ar.ReferenceValue, error) {
	// Gather a list of all reference values independent of the type
	verList := append(metadata.RtmManifest.ReferenceValues, metadata.OsManifest.ReferenceValues...)
	for _, appManifest := range metadata.AppManifests {
		verList = append(verList, appManifest.ReferenceValues...)
	}

	verMap := make(map[string][]ar.ReferenceValue)

	// Iterate through the reference values and sort them into the different types
	for _, v := range verList {
		if v.Type != "SNP Reference Value" && v.Type != "SW Reference Value" && v.Type != "TPM Reference Value" && v.Type != "TDX Reference Value" && v.Type != "SGX Reference Value" {
			return nil, fmt.Errorf("reference value of type %v is not supported", v.Type)
		}
		verMap[v.Type] = append(verMap[v.Type], v)
	}
	return verMap, nil
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) (ar.Result, bool) {

	pem := internal.WriteCertPem(cert)
	log.Warnf("%v", string(pem))

	for _, ext := range cert.Extensions {

		log.Tracef("OID: %v", ext.Id.String())

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
						Expected: strconv.FormatUint(uint64(value), 10),
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
						Expected: strconv.FormatUint(uint64(value), 10),
						Got:      strconv.FormatUint(uint64(ext.Value[3]), 10),
					}, false
				}
			} else {
				log.Tracef("extension %v value[1]: %v does not match expected value 1 or 2 (length of integer)",
					oid, ext.Value[1])
				return ar.Result{Success: false, ErrorCode: ar.OidLength}, false
			}
			return ar.Result{Success: true}, true
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
					Expected: hex.EncodeToString(buf),
					Got:      hex.EncodeToString(ext.Value),
				}, false
			}
			return ar.Result{Success: true}, true
		}
	}

	log.Tracef("extension %v not present in certificate", oid)
	return ar.Result{Success: false, ErrorCode: ar.OidNotPresent}, false
}

func contains(elem string, list []string) bool {
	for _, s := range list {
		if s == elem {
			return true
		}
	}
	return false
}
