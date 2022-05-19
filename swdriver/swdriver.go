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
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

type SwCertRequest struct {
	CertParams []byte
	PubKey     []byte
}

type SwCertResponse struct {
	Certs ar.CertChain
}

// Paths specifies the paths to store the certificates
type Paths struct {
	Leaf        string
	DeviceSubCa string
	Ca          string
}

type Config struct {
	Url      string
	Paths    Paths
	Metadata [][]byte
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

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	certParams, err := getCertParams(c.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert params: %w", err)
	}

	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key returned %w", err)
	}

	certRequest := SwCertRequest{
		CertParams: certParams,
		PubKey:     pub,
	}

	certResponse, err := getCerts(c.Url+"sw-signing/", certRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates from server: %w", err)
	}

	err = saveCerts(c.Paths, certResponse.Certs)
	if err != nil {
		return nil, fmt.Errorf("failed to save certificates: %w", err)
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
		b, _ := ioutil.ReadAll(resp.Body)
		log.Warn("Request failed: body: ", string(b))
		return SwCertResponse{}, fmt.Errorf("request Failed: HTTP Server responded '%v'", resp.Status)
	}

	log.Debug("HTTP Response OK")

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return SwCertResponse{}, fmt.Errorf("error sending params - %v", err)
	}

	var response SwCertResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&response)

	return response, nil
}

func saveCerts(paths Paths, certs ar.CertChain) error {

	log.Tracef("New Leaf Cert %v: %v", paths.Leaf, string(certs.Leaf))
	if err := ioutil.WriteFile(paths.Leaf, certs.Leaf, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.Leaf, err)
	}

	if len(certs.Intermediates) != 1 {
		return fmt.Errorf("SwSigner allows exactly one intermediate (%v provided)", len(certs.Intermediates))
	}
	log.Tracef("New Intermediate Cert %v: %v", paths.DeviceSubCa, string(certs.Intermediates[0]))
	if err := ioutil.WriteFile(paths.DeviceSubCa, certs.Intermediates[0], 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.DeviceSubCa, err)
	}

	log.Tracef("New CA Cert %v: %v", paths.Ca, string(certs.Ca))
	if err := ioutil.WriteFile(paths.Ca, certs.Ca, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.Ca, err)
	}

	return nil
}

func getCertParams(metadata [][]byte) ([]byte, error) {

	for _, m := range metadata {

		jws, err := jose.ParseSigned(string(m))
		if err != nil {
			log.Warnf("Failed to parse Manifest: %v", err)
			continue
		}

		payload := jws.UnsafePayloadWithoutVerification()

		// Unmarshal the Type field of the JSON file to determine the type
		t := new(ar.JSONType)
		err = json.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if t.Type == "TLS Key Cert Params" {
			return m, nil
		}
	}

	return nil, errors.New("failed to find cert params")
}
