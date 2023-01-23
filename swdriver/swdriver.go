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

package swdriver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/sirupsen/logrus"
)

var (
	swProtocolVersion = 2
	log               = logrus.WithField("service", "swdriver")
)

type SwCertRequest struct {
	Version int
	Csr     []byte
	PubKey  []byte
}

type SwCertResponse struct {
	Version int
	Certs   ar.CertChain
}

// Paths specifies the paths to store the certificates
type Paths struct {
	TLSCert     string
	DeviceSubCa string
	Ca          string
}

type Config struct {
	StoragePath string
	Url         string
	Metadata    [][]byte
	Serializer  ar.Serializer
}

// Sw is a struct required for implementing the signer and measurer interfaces
// of the attestation report to perform software measurements and signing
type Sw struct {
	certChain ar.CertChain
	priv      crypto.PrivateKey
}

// NewSwDriver returns a new object for software-based measurements and signing
func NewSwDriver(c Config) (*Sw, error) {
	sw := &Sw{}

	// Check if serializer is initialized
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return nil, fmt.Errorf("serializer not initialized in driver config")
	}

	caPath, err := createLocalStorage(c.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create local storage: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	csr, err := createCsr(&c, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert params: %w", err)
	}

	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key returned %w", err)
	}

	certRequest := SwCertRequest{
		Version: swProtocolVersion,
		Csr:     csr,
		PubKey:  pub,
	}

	certResponse, err := getCerts(c.Url+"sw-signing/", certRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates from server: %w", err)
	}

	if certResponse.Version != swProtocolVersion {
		return nil, fmt.Errorf("response protocol version (%v) does not match our protocol version (%v)",
			certResponse.Version, swProtocolVersion)
	}

	err = os.WriteFile(caPath, certResponse.Certs.Ca, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write file %v: %w", caPath, err)
	}

	sw.certChain = certResponse.Certs
	sw.priv = priv

	return sw, nil
}

// Lock implements the locking method for the attestation report signer interface
func (s *Sw) Lock() {
	// No locking mechanism required for software key
}

// Lock implements the unlocking method for the attestation report signer interface
func (s *Sw) Unlock() {
	// No unlocking mechanism required for software key
}

// GetSigningKeys returns the TLS private and public key as a generic
// crypto interface
func (s *Sw) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *Sw) GetCertChain() ar.CertChain {
	return s.certChain
}

func getCerts(url string, req SwCertRequest) (SwCertResponse, error) {
	var buf bytes.Buffer
	e := gob.NewEncoder(&buf)
	if err := e.Encode(req); err != nil {
		return SwCertResponse{}, fmt.Errorf("failed to send request to server: %v", err)
	}

	log.Debugf("Sending CSR HTTP POST Request to %v", url)

	resp, err := http.Post(url, "signing/csr", &buf)
	if err != nil {
		return SwCertResponse{}, fmt.Errorf("error sending params - %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Warn("Request failed: body: ", string(b))
		return SwCertResponse{}, fmt.Errorf("request Failed: HTTP Server responded '%v'", resp.Status)
	}

	log.Debug("HTTP Response OK")

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return SwCertResponse{}, fmt.Errorf("error sending params - %v", err)
	}

	var response SwCertResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&response)

	return response, nil
}

func createCsr(c *Config, priv crypto.PrivateKey) ([]byte, error) {

	for i, m := range c.Metadata {

		// Extract plain payload (i.e. the manifest/description itself)
		payload, err := c.Serializer.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata file to determine the type
		t := new(ar.Type)
		err = c.Serializer.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if t.Type == "TLS Key Cert Params" {
			var certParams ar.CertParams
			err = c.Serializer.Unmarshal(payload, &certParams)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal CertParams: %w", err)
			}
			csr, err := createCsrFromParams(priv, certParams)
			if err != nil {
				return nil, fmt.Errorf("failed to create CSR: %w", err)
			}
			return csr, nil
		}
	}

	return nil, errors.New("failed to find cert params")
}

func createCsrFromParams(priv crypto.PrivateKey, params ar.CertParams) ([]byte, error) {

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
	pemCert := &bytes.Buffer{}
	pem.Encode(pemCert, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return pemCert.Bytes(), nil
}

func createLocalStorage(storagePath string) (string, error) {

	// Create storage folder for storage of internal data if not existing
	if _, err := os.Stat(storagePath); err != nil {
		if err := os.MkdirAll(storagePath, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory for internal data '%v': %w",
				storagePath, err)
		}
	}

	return path.Join(storagePath, "ca.pem"), nil
}
