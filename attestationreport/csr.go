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

// Install github packages with "go get [url]"
import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
)

func CreateCsr(priv crypto.PrivateKey, s Serializer, metadata [][]byte) (*x509.CertificateRequest, error) {

	for i, m := range metadata {

		// Extract plain payload (i.e. the manifest/description itself)
		payload, err := s.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata file to determine the type
		t := new(Type)
		err = s.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if t.Type == "Device Config" {
			var deviceConfig DeviceConfig
			err = s.Unmarshal(payload, &deviceConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal DeviceConfig: %w", err)
			}
			csr, err := createCsrFromParams(priv, deviceConfig.IkCsr)
			if err != nil {
				return nil, fmt.Errorf("failed to create CSR: %w", err)
			}
			return csr, nil
		}
	}

	return nil, errors.New("failed to find device config for creating CSRs")
}

func createCsrFromParams(priv crypto.PrivateKey, params CsrParams,
) (*x509.CertificateRequest, error) {

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         params.Subject.CommonName,
			Country:            []string{params.Subject.Country},
			Province:           []string{params.Subject.Province},
			Locality:           []string{params.Subject.Locality},
			Organization:       []string{params.Subject.Organization},
			OrganizationalUnit: []string{params.Subject.OrganizationalUnit},
			StreetAddress:      []string{params.Subject.StreetAddress},
			PostalCode:         []string{params.Subject.PostalCode},
		},
		DNSNames: params.SANs,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return csr, nil
}
