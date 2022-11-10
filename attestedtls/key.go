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

package attestedtls

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	// local modules
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
	// debug
	"encoding/hex"
)

// Converts Hash Types from crypto.SignerOpts to the types specified in the CMC interface
func convertHash(opts crypto.SignerOpts) (ci.HashFunction, error) {
	switch opts.HashFunc() {
	case crypto.MD4:
		return ci.HashFunction_MD4, nil
	case crypto.MD5:
		return ci.HashFunction_MD5, nil
	case crypto.SHA1:
		return ci.HashFunction_SHA1, nil
	case crypto.SHA224:
		return ci.HashFunction_SHA224, nil
	case crypto.SHA256:
		return ci.HashFunction_SHA256, nil
	case crypto.SHA384:
		return ci.HashFunction_SHA384, nil
	case crypto.SHA512:
		return ci.HashFunction_SHA512, nil
	case crypto.MD5SHA1:
		return ci.HashFunction_MD5SHA1, nil
	case crypto.RIPEMD160:
		return ci.HashFunction_RIPEMD160, nil
	case crypto.SHA3_224:
		return ci.HashFunction_SHA3_224, nil
	case crypto.SHA3_256:
		return ci.HashFunction_SHA3_256, nil
	case crypto.SHA3_384:
		return ci.HashFunction_SHA3_384, nil
	case crypto.SHA3_512:
		return ci.HashFunction_SHA3_512, nil
	case crypto.SHA512_224:
		return ci.HashFunction_SHA512_224, nil
	case crypto.SHA512_256:
		return ci.HashFunction_SHA512_256, nil
	case crypto.BLAKE2s_256:
		return ci.HashFunction_BLAKE2s_256, nil
	case crypto.BLAKE2b_256:
		return ci.HashFunction_BLAKE2b_256, nil
	case crypto.BLAKE2b_384:
		return ci.HashFunction_BLAKE2b_384, nil
	case crypto.BLAKE2b_512:
		return ci.HashFunction_BLAKE2b_512, nil
	default:
	}
	return ci.HashFunction_SHA512, errors.New("[PrivateKey] Could not determine correct Hash function")
}

// PrivateKey Wrapper Implementing crypto.Signer interface
// Used to contact cmcd for signing operations
type PrivateKey struct {
	cmcConfig // embedded struct
	pubKey    crypto.PublicKey
}

// Implementation of Sign() in crypto.Signer iface
// Contacts cmcd for sign operation and returns received signature
func (priv PrivateKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Get backend connection
	cmcClient, conn, cancel := getCMCServiceConn(priv.cmcConfig)
	if cmcClient == nil {
		return nil, errors.New("[PrivateKey] Connection failed. No signing performed")
	}
	defer conn.Close()
	defer cancel()
	log.Info("[PrivateKey] Contacting backend for Sign Operation")

	// Create Sign request
	hash, err := convertHash(opts)
	if err != nil {
		return nil, fmt.Errorf("[Private Key] Sign request creation failed: %w", err)
	}
	req := ci.TLSSignRequest{
		Id:       id,
		Content:  digest,
		Hashtype: hash,
	}

	// parse additional signing options - not implemented fields assume recommend defaults
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		req.PssOpts = &ci.PSSOptions{SaltLength: int32(pssOpts.SaltLength)}
	}

	// Send Sign request
	resp, err := cmcClient.TLSSign(context.Background(), &req)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}

	// Check Sign response
	if resp.GetStatus() != ci.Status_OK {
		return nil, fmt.Errorf("signature creation failed with status %v", resp.GetStatus())
	}
	log.Trace("[PrivateKey] signature: \n ", hex.EncodeToString(resp.GetSignedContent()))
	return resp.GetSignedContent(), nil
}

func (priv PrivateKey) Public() crypto.PublicKey {
	return priv.pubKey
}

// Obtains Certificate for the used TLS key from cmcd
func GetCert(moreConfigs ...ConnectionOption[cmcConfig]) (tls.Certificate, error) {
	var tlsCert tls.Certificate

	// get cmc Config: start with defaults
	cc := cmcConfig{
		cmcAddress: cmcAddressDefault,
		cmcPort:    cmcPortDefault,
	}
	for _, c := range moreConfigs {
		c(&cc)
	}

	// Get backend connection
	cmcClient, cmcconn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return tls.Certificate{}, errors.New("[Listener] Connection failed. No Cert obtained")
	}
	defer cmcconn.Close()
	defer cancel()

	// Create TLSCert request
	req := ci.TLSCertRequest{
		Id: id,
	}

	// Call TLSCert request
	resp, err := cmcClient.TLSCert(context.Background(), &req)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to request TLS certificate: %w", err)
	}

	// Check TLSCert response
	if resp.GetStatus() != ci.Status_OK || len(resp.GetCertificate()) == 0 {
		return tls.Certificate{}, errors.New("could not receive TLS certificate")
	}

	// Convert each certificate (assuming it has superfluous "---------[]BEGIN CERTIFICATE[]-----" still there)
	for _, cert := range resp.GetCertificate() {
		var currentBlock *pem.Block
		var remain []byte
		currentBlock, remain = pem.Decode(cert)
		if currentBlock == nil {
			return tls.Certificate{}, errors.New("certificate inside the certificate chain could not be decoded")
		}
		if newBlock, _ := pem.Decode(remain); newBlock != nil {
			return tls.Certificate{}, errors.New("certificate inside certificate chain contain superfluous data. Expecting separate Certificates")
		}
		if currentBlock.Type == "CERTIFICATE" {
			tlsCert.Certificate = append(tlsCert.Certificate, currentBlock.Bytes)
		} else {
			return tls.Certificate{}, errors.New("certificate inside the certificate chain not of correct type")
		}
	}
	if len(tlsCert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("could not parse any certificate")
	}

	// Convert TLS cert (first cert) only to obtain its crypto.PublicKey
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse certificate: %w", err)
	}

	log.Tracef("Retrieved TLS certificate %v with SANS %v", x509Cert.Subject.CommonName, x509Cert.DNSNames)

	// Create TLS Cert
	tlsCert.PrivateKey = PrivateKey{
		pubKey: x509Cert.PublicKey,
		cmcConfig: cmcConfig{
			cmcAddress: cc.cmcAddress,
			cmcPort:    cc.cmcPort,
		},
	}
	// return cert
	return tlsCert, nil
}
