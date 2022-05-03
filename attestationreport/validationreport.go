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

package attestationreport

// VerificationResult represents the results of all steps taken during
// the validation of an attestation report
type VerificationResult struct {
	Type            string            `json:"type"`
	Success         bool              `json:"raSuccessful"`         // Summarizing value illustrating whether any issues were detected during validation
	SwCertLevel     int               `json:"swCertLevel"`          // Overall certification level for the entire software stack (the minimum of all CertificationLevels in the used manifests)
	FreshnessCheck  Result            `json:"freshnessCheck"`       // Result for comparison of the expected nonce to the one provided in the attestation report
	ReportSignature []SignatureResult `json:"reportSignatureCheck"` // Result for validation of the overall report signature
	CompDescResult  *CompDescResult   `json:"companyValidation,omitempty"`
	RtmResult       ManifestResult    `json:"rtmValidation"`
	OsResult        ManifestResult    `json:"osValidation"`
	AppResults      []ManifestResult  `json:"appValidation,omitempty"`
	MeasResult      MeasurementResult `json:"measurementValidation"`
	DevDescResult   DevDescResult     `json:"deviceDescValidation"`
	ProcessingError []string          `json:"processingError,omitempty"`  // used to document any processing errors (dependent from provided Attestation Report) which hindered a complete validation
	InternalError   bool              `json:"internalError,omitempty"`    // used to document if internal errors (independent from provided Attestation Report) occurred which hindered a complete validation
	PlainAttReport  ArPlain           `json:"validatedAttestationReport"` // The unpacked and validated attestation report content for further processing
}

// CompDescResult represents the results of the validation of the
// Company Description and its mapping to the used device certificate
type CompDescResult struct {
	Name           string            `json:"name"`
	CompCertLevel  int               `json:"compCertLevel"` // Overall certification level for the company operating the device
	Summary        ResultMulti       `json:"resultSummary"`
	SignatureCheck []SignatureResult `json:"signatureValidation"` // Results for validation of the Description Signatures and the used certificates
	ValidityCheck  Result            `json:"validityCheck"`       // Result from checking the validity of the manifest
}

// ManifestResult represents the results of the validation of a
// manifest provided in the Attestation Report
type ManifestResult struct {
	Name           string            `json:"name"`
	Summary        ResultMulti       `json:"resultSummary"`
	SignatureCheck []SignatureResult `json:"signatureValidation"` // Results for validation of the Manifest Signatures and the used certificates
	ValidityCheck  Result            `json:"validityCheck"`       // Result from checking the validity of the manifest
}

// MeasurementResult represents the results of the comparison of
// verifications and measurements. The used attributes depend on
// the technologies used for calculating the measurements
type MeasurementResult struct {
	TpmMeasResult *TpmMeasurementResult `json:"tpm,omitempty"`
	SnpMeasResult *SnpMeasurementResult `json:"snp,omitempty"`
	SwMeasResult  []SwMeasurementResult `json:"sw,omitempty"`
}

// DevDescResult represents the results of the validation of the
// Device Description in the Attestation Report
type DevDescResult struct {
	Summary             ResultMulti       `json:"resultSummary"`
	CorrectRtm          Result            `json:"correctRtm"`               // Result for comparison of RTM in the Device Description and the provided RTM Manifest
	CorrectOs           Result            `json:"correctOs"`                // Result for comparison of OS in the Device Description and the provided OS Manifest
	CorrectApps         ResultMulti       `json:"correctApps"`              // Result for comparison of App List in the Device Description and the provided App Manifest
	RtmOsCompatibility  Result            `json:"rtmOsCompatibility"`       // Result for consistency check for mapping from OS Manifest to RTM Manifest
	OsAppsCompatibility ResultMulti       `json:"osAppCompatibility"`       // Result for consistency check for mapping from App Manifests to OS Manifest
	SignatureCheck      []SignatureResult `json:"signatureValidation"`      // Results for validation of the Device Description Signature(s) and the used certificates
	OpAffiliation       Result            `json:"operatorAffiliationCheck"` // Result for comparison of the device and the operator affiliation (based on "organization" field in the identity certificates)
}

// TpmMeasurementResults represents the results of the validation
// of the provided TPM Quote and its comparison to the verifications in the manifests
type TpmMeasurementResult struct {
	Summary            Result          `json:"resultSummary"`
	PcrRecalculation   []PcrResult     `json:"pcrRecalculation"`   // Result for validation whether the measured PCR values match the provided verifications
	AggPcrQuoteMatch   Result          `json:"aggPcrQuoteMatch"`   // Result for comparing the aggregated PCR values with the value in the TPM Quote
	QuoteFreshness     Result          `json:"quoteFreshness"`     // Result for comparison of the expected nonce to the one provided in the TPM Quote
	QuoteSignature     SignatureResult `json:"quoteSignature"`     // Results for validation of the TPM Quote Signature and the used certificates
	VerificationsCheck ResultMulti     `json:"verificationsCheck"` // Checks that every TPM verification was part of the measurements
}

// PcrResult represents the results for the recalculation of a specific PCR
type PcrResult struct {
	Pcr        int         `json:"pcr"` // Number for the PCR which was validated
	Validation ResultMulti `json:"validation"`
}

// SwMeasurementResult represents the results for the verification of
// a software measurement (currently only used for app verifications)
type SwMeasurementResult struct {
	MeasName   string `json:"measurementName"`  // Name associated with the measurement used for validation
	VerName    string `json:"verificationName"` // Name of the verification information used for validation
	Validation Result `json:"validation"`
}

// SnpMeasurementResult represents the results for the verification
// of AMD SEV SNP measurements
type SnpMeasurementResult struct {
	Summary            Result          `json:"resultSummary"`
	Freshness          Result          `json:"freshness"`
	Signature          SignatureResult `json:"signature"`
	MeasurementMatch   Result          `json:"measurementMatch"`
	ParamsMatch        Result          `json:"paramsMatch"`
	VerificationsCheck ResultMulti     `json:"verificationsCheck"` // Checks that every SNP verification was part of the measurements
}

// SignatureResults represents the results for validation of
// a provided signature and the used certificates
type SignatureResult struct {
	Name            string       `json:"commonName"`            // Name of the certificate used for calculating the signature
	Organization    []string     `json:"organization"`          // Name of the organization the signer belongs to
	Signature       Result       `json:"signatureVerification"` // Result from checking the signature has been calculated with this certificate
	CertCheck       Result       `json:"certChainValidation"`   // Result from validatint the certification chain back to a shared root of trust
	RoleCheck       *Result      `json:"roleCheck,omitempty"`   // Result for checking the role in the certificate (optional)
	ExtensionsCheck *ResultMulti `json:"extensionsCheck,omitempty"`
}

// Result is a generic type for storing a boolean result value
// and details on the validation (used in case of errors)
type Result struct {
	Success bool   `json:"success"`
	Details string `json:"details,omitempty"` // Details on the issue which was detected during validation, remains empty if validation was successful
}

// ResultMulti is a generic type for storing a boolean result value
// and possibly multiple details on the validation (used in case of errors)
type ResultMulti struct {
	Success bool     `json:"success"`
	Details []string `json:"details,omitempty"` // Details on the issue which was detected during validation, remains empty if validation was successful
}

// JwsResult is a helper struct for the validation of JWS focussing on the validation of the provided signatures
type JwsResult struct {
	Summary        ResultMulti       `json:"resultSummary"`
	SignatureCheck []SignatureResult `json:"signatureValidation"`
}
