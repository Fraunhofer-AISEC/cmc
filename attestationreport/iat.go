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

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/veraison/go-cose"
)

type SwComponent struct {
	MeasurementType        string `cbor:"1,keyasint"`
	MeasurementValue       []byte `cbor:"2,keyasint"`
	Version                string `cbor:"4,keyasint"`
	SignerId               []byte `cbor:"5,keyasint"`
	MeasurementDescription string `cbor:"6,keyasint"`
}

type Iat struct {
	ProfileDefinition string        `cbor:"-75000,keyasint"`
	ClientId          int           `cbor:"-75001,keyasint"`
	LifeCycle         uint16        `cbor:"-75002,keyasint"`
	ImplementationId  [32]byte      `cbor:"-75003,keyasint"`
	BootSeed          [32]byte      `cbor:"-75004,keyasint"`
	HwVersion         string        `cbor:"-75005,keyasint"`
	SwComponents      []SwComponent `cbor:"-75006,keyasint"`
	NoSwMeasurements  int           `cbor:"-75007,keyasint"`
	AuthChallenge     []byte        `cbor:"-75008,keyasint"`
	InstanceId        [33]byte      `cbor:"-75009,keyasint"`
	Vsi               string        `cbor:"-75010,keyasint,omitempty"`
}

func verifyIasMeasurements(iasM *IasMeasurement, nonce []byte, referenceValues []ReferenceValue,
	cas []*x509.Certificate,
) (*IasMeasurementResult, bool) {
	result := &IasMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither IAS measurements, nor IAS Reference Values
	// there is nothing to to
	if iasM == nil && len(referenceValues) == 0 {
		return nil, true
	}

	// If the attestationreport contains IAS Reference Values, but no IAS measurement, the
	// attestation must fail
	if iasM == nil {
		for _, v := range referenceValues {
			result.Artifacts = append(result.Artifacts,
				DigestResult{
					Name:    v.Name,
					Digest:  hex.EncodeToString(v.Sha256),
					Success: false,
					Type:    "Reference Value",
				})
		}
		msg := "IAS Measurement not present"
		result.Summary.setFalse(&msg)
		return result, false
	}

	log.Tracef("Parsing %v certificates", len(iasM.Certs))
	certs, err := internal.ParseCertsDer(iasM.Certs)
	if err != nil {
		msg := fmt.Sprintf("failed to parse IAS certificates: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	if len(referenceValues) == 0 {
		msg := "Could not find IAS Reference Value"
		result.Summary.setFalse(&msg)
		return result, false
	}
	s := CborSerializer{}

	log.Trace("Verifying CBOR IAT")

	iatresult, payload, ok := verifyIat(iasM.Report, certs[0])
	if !ok {
		msg := "IAS signature verification failed"
		result.Summary.setFalse(&msg)
		return result, false
	}
	result.IasSignature = iatresult

	log.Trace("Unmarshalling CBOR IAT")

	iat := &Iat{}
	err = s.Unmarshal(payload, iat)
	if err != nil {
		msg := fmt.Sprintf("Failed to unmarshal IAT: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	log.Trace("Verifying nonce")

	// Verify nonce
	if bytes.Equal(nonce, iat.AuthChallenge) {
		result.FreshnessCheck.Success = true
	} else {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, IAT Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(iat.AuthChallenge))
		result.FreshnessCheck.setFalse(&msg)
		ok = false
	}

	log.Trace("Verifying certificate chain")

	// Verify certificate chain
	x509Chains, err := internal.VerifyCertChain(certs, cas)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.IasSignature.CertChainCheck.setFalse(&msg)
		ok = false
	} else {
		result.IasSignature.CertChainCheck.Success = true
	}

	//Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
		}
		result.IasSignature.ValidatedCerts = append(result.IasSignature.ValidatedCerts, chainExtracted)
	}

	result.Summary.Success = ok

	log.Trace("Verifying measurements")

	// Verify that every reference value has a corresponding measurement
	for _, ver := range referenceValues {
		log.Tracef("Found reference value %v: %v", ver.Name, hex.EncodeToString(ver.Sha256))
		if ver.Type != "IAS Reference Value" {
			msg := fmt.Sprintf("IAS Reference Value invalid type %v", ver.Type)
			result.Summary.setFalse(&msg)
			return result, false
		}
		found := false
		for _, swc := range iat.SwComponents {
			if bytes.Equal(ver.Sha256, swc.MeasurementValue) {
				result.Artifacts = append(result.Artifacts,
					DigestResult{
						Name:    ver.Name,
						Digest:  hex.EncodeToString(ver.Sha256),
						Success: true,
					})
				found = true
			}
		}
		if !found {
			ok = false
			result.Artifacts = append(result.Artifacts,
				DigestResult{
					Name:    ver.Name,
					Digest:  hex.EncodeToString(ver.Sha256),
					Success: false,
					Type:    "Reference Value",
				})
		}
	}

	// Verify that every measurement has a corresponding reference value
	for _, swc := range iat.SwComponents {
		log.Tracef("Found measurement %v: %v", swc.MeasurementDescription,
			hex.EncodeToString(swc.MeasurementValue))
		found := false
		for _, ver := range referenceValues {
			if bytes.Equal(ver.Sha256, swc.MeasurementValue) {
				result.Artifacts = append(result.Artifacts, DigestResult{
					Name:    ver.Name,
					Digest:  hex.EncodeToString(swc.MeasurementValue),
					Success: true,
				})
				found = true
			}
		}
		if !found {
			ok = false
			result.Artifacts = append(result.Artifacts, DigestResult{
				Name:    swc.MeasurementDescription,
				Digest:  hex.EncodeToString(swc.MeasurementValue),
				Success: false,
				Type:    "Measurement",
			})
		}
	}

	return result, ok
}

func verifyIat(data []byte, cert *x509.Certificate) (SignatureResult, []byte, bool) {

	result := SignatureResult{
		CertChainCheck: Result{Success: true},
	}

	// create a Sign1Message from a raw COSE_Sign payload
	var msgToVerify cose.Sign1Message
	err := msgToVerify.UnmarshalCBOR(data)
	if err != nil {
		log.Warnf("error unmarshalling cose: %v", err)
		return result, nil, false
	}

	publicKey, okKey := cert.PublicKey.(*ecdsa.PublicKey)
	if !okKey {
		msg := fmt.Sprintf("Failed to extract public key from certificate: %v", err)
		result.SignCheck.setFalse(&msg)
		return result, nil, false
	}

	// create a verifier from a trusted private key
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		msg := fmt.Sprintf("Failed to create verifier: %v", err)
		result.SignCheck.setFalse(&msg)
		return result, nil, false
	}

	err = msgToVerify.Verify(nil, verifier)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify COSE token: %v", err)
		result.SignCheck.setFalse(&msg)
		return result, nil, false
	}

	result.SignCheck.Success = true

	return result, msgToVerify.Payload, true
}
