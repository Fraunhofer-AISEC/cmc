// Copyright (c) 2025 Fraunhofer AISEC
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

package selfsigned

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	"go.mozilla.org/pkcs7"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
)

type Client struct {
	caPriv  crypto.PrivateKey
	caChain []*x509.Certificate
	snpConf *provision.SnpConfig
	tpmConf *provision.TpmConfig
}

func New(caKey crypto.PrivateKey, caChain []*x509.Certificate, vcekCache,
	ekDbPath string, verifyEkCert bool,
) (*Client, error) {

	return &Client{
		caPriv:  caKey,
		caChain: caChain,
		snpConf: &provision.SnpConfig{
			VcekCacheFolder: vcekCache,
			Vceks:           make(map[provision.VcekInfo][]byte),
		},
		tpmConf: &provision.TpmConfig{
			VerifyEkCert: false,
			DbPath:       ekDbPath,
		},
	}, nil
}

func (c *Client) CaCerts() ([]*x509.Certificate, error) {
	return c.caChain, nil
}

func (c *Client) SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error) {

	tmpl, err := internal.CreateCert(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert from CSR: %w", err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, c.caChain[0], csr.PublicKey, c.caPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, nil
}

func (c *Client) TpmActivateEnroll(
	tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akParams attest.AttestationParameters,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {

	// Create string with TPM info required for the server to find the
	// correct EK certificate chain
	tpmInfo := fmt.Sprintf("%v;%v;%v", tpmManufacturer, tpmMajor, tpmMinor)

	err := provision.VerifyEk(ekPublic, ekCertDer, tpmInfo, ekCertUrl, c.tpmConf.DbPath, c.tpmConf.VerifyEkCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify EK: %w", err)
	}

	ekPub, err := x509.ParsePKIXPublicKey(ekPublic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse PKIX public key: %v", err)
	}

	params := attest.ActivationParameters{
		TPMVersion: 2,
		EK:         ekPub,
		AK:         akParams,
	}

	// Generate the credential activation challenge. This includes verifying, that the
	// AK is a restricted, fixedTPM, fixedParent key
	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate AK credentials: %v", err)
	}

	// Verify that activated AK is actually the certificate public key
	err = provision.VerifyTpmCsr(akParams.Public, csr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify AK: %v", err)
	}

	// Enroll cert
	tmpl, err := internal.CreateCert(csr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cert from CSR: %w", err)
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, c.caChain[0], csr.PublicKey, c.caPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	// Encrypt cert
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	encryptedCert, err := pkcs7.EncryptUsingPSK(cert.Raw, secret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt using PSK: %w", err)
	}

	return encryptedCredentials.Credential, encryptedCredentials.Secret, encryptedCert, nil
}

func (c *Client) TpmCertifyEnroll(
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	report []byte,
	metadata [][]byte,
) (*x509.Certificate, error) {

	// Verify the IK was certified by AK
	err := provision.VerifyIk(ikParams, akPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IK: %w", err)
	}

	// Verify that certified IK is actually the CSR public key
	err = provision.VerifyTpmCsr(ikParams.Public, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IK: %w", err)
	}

	tmpl, err := internal.CreateCert(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert from CSR: %w", err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, c.caChain[0], csr.PublicKey, c.caPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, nil
}

func (c *Client) CcEnroll(
	csr *x509.CertificateRequest,
	report []byte,
	metadata [][]byte,
) (*x509.Certificate, error) {

	// self-attestation is not required in the self-signed testing mode
	return c.SimpleEnroll(csr)
}

func (c *Client) GetSnpCa(codeName string, akType internal.AkType) ([]*x509.Certificate, error) {

	ca, err := c.snpConf.GetSnpCa(codeName, akType)
	if err != nil {
		return nil, fmt.Errorf("failed to get VCEK: %w", err)
	}

	return ca, nil
}

func (c *Client) GetSnpVcek(codeName string, chipId [64]byte, tcb uint64) (*x509.Certificate, error) {

	vcek, err := c.snpConf.GetVcek(codeName, chipId[:], tcb)
	if err != nil {
		return nil, fmt.Errorf("failed to get VCEK: %w", err)
	}

	return vcek, nil
}
