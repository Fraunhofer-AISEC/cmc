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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
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

func verifyIasMeasurements(iasM ar.Measurement, nonce []byte, cas []*x509.Certificate,
	referenceValues []ar.ReferenceValue,
) (*ar.MeasurementResult, bool) {

	result := &ar.MeasurementResult{
		Type: "IAT Result",
	}
	ok := true

	log.Tracef("Parsing %v certificates", len(iasM.Certs))
	certs, err := internal.ParseCertsDer(iasM.Certs)
	if err != nil {
		log.Tracef("failed to parse IAS certificates: %v", err)
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	if len(referenceValues) == 0 {
		log.Tracef("Could not find IAS Reference Value")
		result.Summary.SetErr(ar.RefValNotPresent)
		return result, false
	}
	s := ar.CborSerializer{}

	log.Trace("Verifying CBOR IAT")

	iatresult, payload, ok := verifyIat(iasM.Evidence, certs[0])
	if !ok {
		log.Tracef("IAS signature verification failed")
		result.Summary.SetErr(ar.VerifySignature)
		return result, false
	}
	result.Signature.SignCheck = iatresult

	log.Trace("Unmarshalling CBOR IAT")

	iat := &Iat{}
	err = s.Unmarshal(payload, iat)
	if err != nil {
		log.Tracef("Failed to unmarshal IAT: %v", err)
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	log.Trace("Verifying nonce")

	// Verify nonce
	if bytes.Equal(nonce, iat.AuthChallenge) {
		result.Freshness.Success = true
	} else {
		log.Tracef("Nonces mismatch: Supplied Nonce = %v, IAT Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(iat.AuthChallenge))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(iat.AuthChallenge)
		ok = false
	}

	log.Trace("Verifying certificate chain")

	// Verify certificate chain
	x509Chains, err := internal.VerifyCertChain(certs, cas)
	if err != nil {
		log.Tracef("Failed to verify certificate chain: %v", err)
		result.Signature.CertChainCheck.SetErr(ar.VerifyCertChain)
		ok = false
	} else {
		result.Signature.CertChainCheck.Success = true
	}

	//Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []ar.X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ar.ExtractX509Infos(cert))
		}
		result.Signature.ValidatedCerts = append(result.Signature.ValidatedCerts, chainExtracted)
	}

	result.Summary.Success = ok

	log.Trace("Verifying measurements")

	// Verify that every reference value has a corresponding measurement
	for _, ver := range referenceValues {
		log.Tracef("Found reference value %v: %v", ver.Name, hex.EncodeToString(ver.Sha256))
		if ver.Type != "IAS Reference Value" {
			log.Tracef("IAS Reference Value invalid type %v", ver.Type)
			result.Summary.SetErr(ar.RefValType)
			return result, false
		}
		found := false
		for _, swc := range iat.SwComponents {
			if bytes.Equal(ver.Sha256, swc.MeasurementValue) {
				result.Artifacts = append(result.Artifacts,
					ar.DigestResult{
						Name:     ver.Name,
						Digest:   hex.EncodeToString(ver.Sha256),
						Success:  true,
						Launched: true,
					})
				found = true
			}
		}
		if !found {
			ok = false
			result.Artifacts = append(result.Artifacts,
				ar.DigestResult{
					Name:     ver.Name,
					Digest:   hex.EncodeToString(ver.Sha256),
					Success:  false,
					Launched: false,
					Type:     "Reference Value",
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
				result.Artifacts = append(result.Artifacts, ar.DigestResult{
					Name:     ver.Name,
					Digest:   hex.EncodeToString(swc.MeasurementValue),
					Success:  true,
					Launched: true,
				})
				found = true
			}
		}
		if !found {
			ok = false
			result.Artifacts = append(result.Artifacts, ar.DigestResult{
				Name:     swc.MeasurementDescription,
				Digest:   hex.EncodeToString(swc.MeasurementValue),
				Success:  false,
				Launched: true,
				Type:     "Measurement",
			})
		}
	}

	return result, ok
}

func verifyIat(data []byte, cert *x509.Certificate) (ar.Result, []byte, bool) {

	// create a Sign1Message from a raw COSE_Sign payload
	var msgToVerify cose.Sign1Message
	err := msgToVerify.UnmarshalCBOR(data)
	if err != nil {
		log.Tracef("error unmarshalling cose: %v", err)
		return ar.Result{Success: false, ErrorCode: ar.ParseEvidence}, nil, false
	}

	publicKey, okKey := cert.PublicKey.(*ecdsa.PublicKey)
	if !okKey {
		log.Tracef("Failed to extract public key from certificate: %v", err)
		return ar.Result{Success: false, ErrorCode: ar.ExtractPubKey}, nil, false
	}

	// create a verifier from a trusted private key
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		log.Tracef("Failed to create verifier: %v", err)
		return ar.Result{Success: false, ErrorCode: ar.Internal}, nil, false
	}

	err = msgToVerify.Verify(nil, verifier)
	if err != nil {
		log.Tracef("Failed to verify COSE token: %v", err)
		return ar.Result{Success: false, ErrorCode: ar.VerifySignature}, nil, false
	}

	return ar.Result{Success: true}, msgToVerify.Payload, true
}
