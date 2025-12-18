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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
)

func GetDeviceConfig(s Serializer, metadata map[string][]byte, cas []*x509.Certificate,
) (*DeviceConfig, error) {

	for i, m := range metadata {

		unverified, err := s.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata file to determine the type
		info := new(MetaInfo)
		err = s.Unmarshal(unverified, info)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if info.Type == "Device Config" {

			_, payload, ok := s.Verify(m, cas)
			if !ok {
				return nil, fmt.Errorf("validation of device config failed")
			}

			deviceConfig := new(DeviceConfig)
			err = s.Unmarshal(payload, deviceConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal DeviceConfig: %w", err)
			}
			return deviceConfig, nil
		}
	}

	return nil, errors.New("failed to find device config for creating CSRs")
}

func CreateCsr(priv crypto.PrivateKey, params CsrParams,
) (*x509.CertificateRequest, error) {

	var ipAddresses []net.IP
	for _, s := range params.IpAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse IP %v", s)
		}
		ipAddresses = append(ipAddresses, ip)
	}

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
		DNSNames:    params.DnsNames,
		IPAddresses: ipAddresses,
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
