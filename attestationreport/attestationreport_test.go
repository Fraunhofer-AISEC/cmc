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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var (
	vers = []ReferenceValue{
		{Type: "TPM Reference Value", Name: "TPM1"},
		{Type: "TPM Reference Value", Name: "TPM2"},
		{Type: "SNP Reference Value", Name: "SNP1"},
		{Type: "SW Reference Value", Name: "SW1"},
		{Type: "SW Reference Value", Name: "SW2"},
	}

	verMap = map[string][]ReferenceValue{
		"TPM Reference Value": vers[:2],
		"SNP Reference Value": {vers[2]},
		"SW Reference Value":  vers[3:],
	}

	rtmManifest = RtmManifest{
		ReferenceValues: []ReferenceValue{
			vers[0],
			vers[2],
		},
	}

	osManifest = OsManifest{
		ReferenceValues: []ReferenceValue{
			vers[1],
		},
	}

	appManifests = []AppManifest{
		{ReferenceValues: []ReferenceValue{vers[3]}},
		{ReferenceValues: []ReferenceValue{vers[4]}},
	}
)

type SwSigner struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

func (s *SwSigner) Init(c *DriverConfig) error {
	return nil
}

func (s *SwSigner) Measure(nonce []byte) (Measurement, error) {
	return nil, nil
}

func (s *SwSigner) Lock() error {
	return nil
}

func (s *SwSigner) Unlock() error {
	return nil
}

func (s *SwSigner) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *SwSigner) GetCertChain() ([]*x509.Certificate, error) {
	return s.certChain, nil
}

func createCertsAndKeys() (*ecdsa.PrivateKey, []*x509.Certificate, error) {

	// Generate private key and public key for test CA
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	caTmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA Cert",
			Country:      []string{"DE"},
			Province:     []string{"BY"},
			Locality:     []string{"Munich"},
			Organization: []string{"Test Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}

	// Generate private key and certificate for test prover, signed by test CA
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Key Cert",
			Country:      []string{"DE"},
			Province:     []string{"BY"},
			Locality:     []string{"Munich"},
			Organization: []string{"Test Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err = x509.CreateCertificate(rand.Reader, &tmpl, &caTmpl, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}

	return priv, []*x509.Certificate{leaf, ca}, nil
}

func Test_collectReferenceValues(t *testing.T) {
	type args struct {
		ar *ArPlain
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]ReferenceValue
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				ar: &ArPlain{
					RtmManifest:  rtmManifest,
					OsManifest:   osManifest,
					AppManifests: appManifests,
				},
			},
			want:    verMap,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := collectReferenceValues(tt.args.ar)
			if (err != nil) != tt.wantErr {
				t.Errorf("collectReferenceValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("collectReferenceValues() = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	validTdxReferenceValue = []ReferenceValue{
		{
			Type:   "TDX Reference Value",
			Sha256: validTDXMeasurement,
			Tdx: &TDXDetails{
				Version: 0x04,
				Collateral: IntelCollateral{
					TeeType:        tee_type_tdx,
					TcbInfo:        tcb_info_tdx,
					TcbInfoSize:    tcb_info_tdx_size,
					QeIdentity:     qe_identity_tdx,
					QeIdentitySize: qe_identity_tdx_size,
				},
				CaFingerprint: tdxRootCAFingerprint,
				TdId: TDId{
					MrOwner:       mrOwner,
					MrOwnerConfig: mrOwnerConfig,
					MrConfigId:    mrConfigId,
					RtMr0:         rtMr0,
					RtMr1:         rtMr1,
					RtMr2:         rtMr2,
					RtMr3:         rtMr3,
				},
				MrSeam:       validMrSeam,
				TdAttributes: validTdAttributes,
				Xfam:         validXFAM,
			},
		},
	}

	validTdxRtmManifest = RtmManifest{
		MetaInfo: MetaInfo{
			Type:    "RTM Manifest",
			Name:    "de.test.rtm",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2026-04-10T20:00:00Z",
		},
		Description:        "de.test.rtm",
		CertificationLevel: 3,
		ReferenceValues:    validTdxReferenceValue,
	}

	emptyTdxRtmManifest = RtmManifest{
		MetaInfo: MetaInfo{
			Type:    "RTM Manifest",
			Name:    "de.test.rtm",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2026-04-10T20:00:00Z",
		},
		Description:        "de.test.rtm",
		CertificationLevel: 3,
		ReferenceValues:    []ReferenceValue{},
	}

	validTdxOsManifest = OsManifest{
		MetaInfo: MetaInfo{
			Type:    "OS Manifest",
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2026-04-10T20:00:00Z",
		},
		Description:        "PoC Fraunhofer AISEC TDX Report",
		CertificationLevel: 3,
		Rtms: []string{
			"de.test.rtm",
		},
	}

	invalidTdxOsManifest = OsManifest{
		MetaInfo: MetaInfo{
			Type:    "OS Manifest",
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2026-04-10T20:00:00Z",
		},
		Description:        "PoC Fraunhofer AISEC TDX Report",
		CertificationLevel: 3,
		Rtms: []string{
			"INVALID",
		},
	}

	validTdxDeviceDescription = DeviceDescription{
		MetaInfo: MetaInfo{
			Type:    "Device Description",
			Name:    "test-device.test.de",
			Version: "2023-04-10T20:00:00Z",
		},
		Location:    "Munich, Germany",
		RtmManifest: "de.test.rtm",
		OsManifest:  "de.test.os",
	}

	invalidTdxDeviceDescription = DeviceDescription{
		MetaInfo: MetaInfo{
			Type:    "Device Description",
			Name:    "test-device.test.de",
			Version: "2023-04-10T20:00:00Z",
		},
		Location:    "Munich, Germany",
		RtmManifest: "INVALID",
		OsManifest:  "INVALID",
	}
)

func TestVerify(t *testing.T) {
	type args struct {
		tdxMeas           *TdxMeasurement
		serializer        Serializer
		rtmManifest       RtmManifest
		osManifest        OsManifest
		deviceDescription DeviceDescription
		nonce             []byte
	}
	tests := []struct {
		name string
		args args
		want VerificationResult
	}{
		{
			name: "Valid TDX Report JSON",
			args: args{
				tdxMeas: &TdxMeasurement{
					Type:   "TDX Measurement",
					Report: aisecTDXQuote,
					Certs:  validTDXCertChain,
				},
				serializer:        JsonSerializer{},
				rtmManifest:       validTdxRtmManifest,
				osManifest:        validTdxOsManifest,
				deviceDescription: validTdxDeviceDescription,
				nonce:             validTDXNonce,
			},
			want: VerificationResult{Success: true},
		},
		{
			name: "Valid TDX Report CBOR",
			args: args{
				tdxMeas: &TdxMeasurement{
					Type:   "TDX Measurement",
					Report: aisecTDXQuote,
					Certs:  validTDXCertChain,
				},
				serializer:        CborSerializer{},
				rtmManifest:       validTdxRtmManifest,
				osManifest:        validTdxOsManifest,
				deviceDescription: validTdxDeviceDescription,
				nonce:             validTDXNonce,
			},
			want: VerificationResult{Success: true},
		},
		{
			name: "Nonce mismatch",
			args: args{
				tdxMeas: &TdxMeasurement{
					Type:   "TDX Measurement",
					Report: aisecTDXQuote,
					Certs:  validTDXCertChain,
				},
				serializer:        JsonSerializer{},
				rtmManifest:       validTdxRtmManifest,
				osManifest:        validTdxOsManifest,
				deviceDescription: validTdxDeviceDescription,
				nonce:             []byte{},
			},
			want: VerificationResult{Success: false},
		},
		{
			name: "Invalid Certification Level",
			args: args{
				tdxMeas:           nil,
				serializer:        JsonSerializer{},
				rtmManifest:       emptyTdxRtmManifest,
				osManifest:        validTdxOsManifest,
				deviceDescription: validTdxDeviceDescription,
				nonce:             validTDXNonce,
			},
			want: VerificationResult{Success: false},
		},
		{
			name: "Invalid Device Description",
			args: args{
				tdxMeas: &TdxMeasurement{
					Type:   "TDX Measurement",
					Report: aisecTDXQuote,
					Certs:  validTDXCertChain,
				},
				serializer:        JsonSerializer{},
				rtmManifest:       validTdxRtmManifest,
				osManifest:        validTdxOsManifest,
				deviceDescription: invalidTdxDeviceDescription,
				nonce:             validTDXNonce,
			},
			want: VerificationResult{Success: false},
		},
		{
			name: "Incompatible RTM/OS Manifests",
			args: args{
				tdxMeas: &TdxMeasurement{
					Type:   "TDX Measurement",
					Report: aisecTDXQuote,
					Certs:  validTDXCertChain,
				},
				serializer:        JsonSerializer{},
				rtmManifest:       validTdxRtmManifest,
				osManifest:        invalidTdxOsManifest,
				deviceDescription: validTdxDeviceDescription,
				nonce:             validTDXNonce,
			},
			want: VerificationResult{Success: false},
		},
	}

	logrus.SetLevel(logrus.TraceLevel)

	// Setup Test Keys and Certificates
	log.Trace("Creating Keys and Certificates")
	key, certchain, err := createCertsAndKeys()
	if err != nil {
		log.Errorf("Internal Error: Failed to create testing certs and keys: %v", err)
		return
	}

	swSigner := &SwSigner{
		priv:      key,
		certChain: certchain,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.args.serializer

			// Preparation: Generate a TDX Report
			log.Trace("Generating a TDX Report")

			ar := ArPacked{
				Type:  "Attestation Report",
				Nonce: tt.args.nonce,
				TdxM:  tt.args.tdxMeas,
			}

			// Preparation: create signed manifests and deviceDescription
			rtmManifest, err := s.Marshal(tt.args.rtmManifest)
			if err != nil {
				t.Errorf("failed to marshal the RtmManifest: %v", err)
			}
			osManifest, err := s.Marshal(tt.args.osManifest)
			if err != nil {
				t.Errorf("failed to marshal the OsManifest: %v", err)
			}
			deviceDescription, err := s.Marshal(tt.args.deviceDescription)
			if err != nil {
				t.Errorf("failed to marshal the DeviceDescription: %v", err)
			}
			ar.RtmManifest, err = Sign(rtmManifest, swSigner, s)
			if err != nil {
				t.Errorf("failed to sign the RtmManifest: %v", err)
			}
			ar.OsManifest, err = Sign(osManifest, swSigner, s)
			if err != nil {
				t.Errorf("failed to sign the OsManifest: %v", err)
			}
			ar.DeviceDescription, err = Sign(deviceDescription, swSigner, s)
			if err != nil {
				t.Errorf("failed to sign the DeviceDescription: %v", err)
			}

			report, err := s.Marshal(ar)
			if err != nil {
				t.Errorf("failed to marshal the Attestation Report: %v", err)
			}

			// Preparation: Sign the report
			arSigned, err := Sign(report, swSigner, s)
			if err != nil {
				t.Errorf("Internal Error: Failed to sign Attestion Report: %v", err)
			}

			// Run FUT
			got := Verify(
				arSigned, tt.args.nonce,
				internal.WriteCertPem(certchain[len(certchain)-1]),
				nil, 0)
			if got.Success != tt.want.Success {
				t.Errorf("Result.Success = %v, want %v", got.Success, tt.want.Success)
			}
			fmt.Println(got)
		})
	}
}
