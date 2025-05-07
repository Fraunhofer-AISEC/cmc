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

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/est/common"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"

	log "github.com/sirupsen/logrus"
)

const (
	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
)

type tpmConfig struct {
	verifyEkCert bool
	dbPath       string
}

func verifyEk(pub, cert []byte, tpmInfo, certUrl string, conf *tpmConfig) error {

	// Check that public key was part of the request
	if pub == nil {
		return fmt.Errorf("ek public key from device not present")
	}

	// Parse TPM Info string
	info := strings.Split(tpmInfo, ";")
	if len(info) != 3 {
		return fmt.Errorf("invalid TPM Info format, contains %v parts, expected 3", len(info))
	}
	manufacturer := info[0]
	major, err := strconv.Atoi(info[1])
	if err != nil {
		return fmt.Errorf("invalid TPM info format, %v is not a valid major: %w", info[1], err)
	}
	minor, err := strconv.Atoi(info[2])
	if err != nil {
		return fmt.Errorf("invalid TPM info format, %v is not a valid minor: %w", info[2], err)
	}

	// Verify the EK certificate chain
	if conf.verifyEkCert {
		// Retrieve the EK cert (varies between manufacturers)
		var ekCert *x509.Certificate
		if len(cert) == 0 {
			if certUrl == "" {
				return fmt.Errorf("neither EK Certificate nor certificate URL present")
			}
			// Intel TPMs do not provide their EK certificate but instead a certificate URL from where
			// // the certificate can be retrieved via its public key
			if manufacturer != manufacturerIntel {
				return fmt.Errorf("ek certificate not present and Certificate URL not supported for manufacturer %v",
					manufacturer)
			}
			resp, err := getIntelEkCert(certUrl)
			if err != nil {
				return fmt.Errorf("failed to retrieve Intel TPM EK certificate from Intel server: %w", err)
			}
			ekCert, err = parseIntelEkCert(resp)
			if err != nil {
				return fmt.Errorf("failed to parse Intel EK cert: %w", err)
			}
		} else {
			// Other manufacturers simply provde their cert in an NV index
			ekCert, err = x509.ParseCertificate(cert)
			if err != nil {
				return fmt.Errorf("failed to parse EK certificate: %w", err)
			}
		}

		err := verifyEkCert(conf.dbPath, ekCert, manufacturer, major, minor)
		if err != nil {
			return fmt.Errorf("verify EK certificate chain: error = %w", err)
		}
		log.Debug("verification of EK certificate chain successful")
	} else {
		log.Warn("skipping EK certificate chain validation (turned off via config)")
	}

	return nil
}

func getIntelEkCert(certificateUrl string) ([]byte, error) {

	log.Println("Requesting Cert from ", certificateUrl)

	resp, err := http.Get(certificateUrl)

	if err != nil {
		return nil, fmt.Errorf("error GET: %w", err)
	}
	defer resp.Body.Close()
	log.Println("Response Status: ", resp.Status)
	if resp.StatusCode != 200 {
		return nil, err
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return content, nil
}

type IntelEk struct {
	Pubhash string `json:"pubhash"`
	Cert    string `json:"certificate"`
}

func parseIntelEkCert(data []byte) (*x509.Certificate, error) {

	intelEk := new(IntelEk)
	err := json.Unmarshal(data, intelEk)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Intel EK: %w", err)
	}

	der, err := common.DecodeBase64Url([]byte(intelEk.Cert))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}

	return cert, nil
}

func verifyEkCert(dbpath string, ek *x509.Certificate, manufacturer string, major, minor int) error {
	// Load the TPM EK Certificate database for validating sent EK certificates
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return fmt.Errorf("failed to open EK certificate SQL database: %w", err)
	}
	defer db.Close()

	// Add TPM EK intermediate certs from database to certificate pool
	var intermediates []byte
	var intermediatesPool *x509.CertPool = nil
	err = db.QueryRow("SELECT Certs FROM trustanchors WHERE Manufacturer LIKE ? AND FwMajor=? AND CA=0", manufacturer, major).Scan(&intermediates)
	if err == sql.ErrNoRows {
		log.Debug("TPM EK cert chain does not contain intermediate certificates")
	} else if err != nil {
		return fmt.Errorf("failed to load EK intermediate certs from database: %w", err)
	} else {
		log.Trace("Found Intermediate Certs in DB: ", string(intermediates))

		intermediatesPool = x509.NewCertPool()
		ok := intermediatesPool.AppendCertsFromPEM(intermediates)
		if !ok {
			return errors.New("failed to append intermediate certificates from database")
		}
		log.Debug("Added certificates to intermediates certificate pool")
	}

	// Add TPM EK CA cert from database to certificate pool
	var roots []byte
	err = db.QueryRow("SELECT Certs FROM trustanchors WHERE Manufacturer LIKE ? AND CA=1", manufacturer).Scan(&roots)
	if err != nil {
		return fmt.Errorf("failed to retrieve CA certificate for TPM from %v (Major: %v, Minor: %v): %w", manufacturer, major, minor, err)
	}
	log.Trace("Found Root Certs in DB: ", string(roots))

	rootsPool := x509.NewCertPool()
	ok := rootsPool.AppendCertsFromPEM(roots)
	if !ok {
		return errors.New("failed to append root certificate from database")
	}
	log.Debug("Added certificates to root certificate pool")

	// TODO the ST certificates contain the x509 v3 extension with OID 2.5.29.17
	// which is not handled by default. Check for other certs and decide how to handle
	u := ek.UnhandledCriticalExtensions
	if len(u) == 1 && len(u[0]) == 4 {
		if u[0][0] == 2 && u[0][1] == 5 && u[0][2] == 29 && u[0][3] == 17 {
			ek.UnhandledCriticalExtensions = make([]asn1.ObjectIdentifier, 0)
		}
	}

	chain, err := ek.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return err
	}

	log.Debugf("Successfully verified chain of %v elements", len(chain[0]))
	for i := range chain[0] {
		log.Tracef("\tCertificate CN='%v', Issuer CN='%v'", chain[0][i].Subject.CommonName, chain[0][i].Issuer.CommonName)
	}

	return nil
}

func verifyIk(ikParams attest.CertificationParameters, akPub []byte) error {
	pub, err := tpm2.DecodePublic(akPub)
	if err != nil {
		return fmt.Errorf("decode public failed: %w", err)
	}
	akPubVerify := &rsa.PublicKey{E: int(pub.RSAParameters.Exponent()),
		N: pub.RSAParameters.Modulus()}
	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return fmt.Errorf("cannot access AK's hash function: %w", err)
	}
	opts := attest.VerifyOpts{
		Public: akPubVerify,
		Hash:   hash,
	}
	err = ikParams.Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to certify IK with AK: %w", err)
	}
	log.Debug("Successfully verified IK with AK")

	return nil
}
