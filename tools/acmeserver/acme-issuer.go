// Copyright (c) 2026 Fraunhofer AISEC
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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

type Issuer interface {
	Issue(ctx context.Context, csr *x509.CertificateRequest) ([]byte, error)
}

type LocalCAIssuer struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func NewLocalCAIssuerFromFiles(certPath, keyPath string) (*LocalCAIssuer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block found in CA certificate file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block found in CA key file")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key (expected EC private key): %w", err)
	}

	return &LocalCAIssuer{Cert: cert, Key: key}, nil
}

func NewEphemeralCAIssuer() (*LocalCAIssuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ACME Test Server Ephemeral CA",
			Organization: []string{"Fraunhofer AISEC"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	return &LocalCAIssuer{Cert: cert, Key: key}, nil
}

func (i *LocalCAIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	notBefore := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(OrderLifeTime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.Cert, csr.PublicKey, i.Key)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	var chain bytes.Buffer
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: i.Cert.Raw})
	return chain.Bytes(), nil
}

type UpstreamIssuerConfig struct {
	DirectoryURL   string
	AccountKeyPath string
	Contact        []string
	RootCAs        []byte
}

type UpstreamIssuer struct {
	client     *acme.Client
	AccountURL string
	Directory  acme.Directory
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, bool, error) {
	if path == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generating account key: %w", err)
		}
		return key, true, nil
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, false, fmt.Errorf("no PEM block found in account key file %s", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("parsing account key (expected EC private key): %w", err)
		}
		return key, false, nil

	case errors.Is(err, os.ErrNotExist):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generating account key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, false, fmt.Errorf("marshaling account key: %w", err)
		}
		pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, pemData, 0o600); err != nil {
			return nil, false, fmt.Errorf("writing account key file: %w", err)
		}
		return key, true, nil

	default:
		return nil, false, fmt.Errorf("reading account key file: %w", err)
	}
}

func NewUpstreamIssuer(ctx context.Context, cfg UpstreamIssuerConfig) (*UpstreamIssuer, error) {
	if cfg.DirectoryURL == "" {
		return nil, fmt.Errorf("upstream directory URL must not be empty")
	}

	key, created, err := loadOrCreateAccountKey(cfg.AccountKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading upstream account key: %w", err)
	}
	if created && cfg.AccountKeyPath != "" {
		log.Printf("Generated new upstream account key at %s", cfg.AccountKeyPath)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(cfg.RootCAs) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.RootCAs) {
			return nil, fmt.Errorf("no certificates found in upstream root CA bundle")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: cfg.DirectoryURL,
		HTTPClient:   &http.Client{Transport: transport, Timeout: UpstreamRequestTimeout},
		UserAgent:    "cmc-acmeserver",
	}

	dir, err := client.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching upstream directory %s: %w", cfg.DirectoryURL, err)
	}

	// Register the proxy account (existing accounts (same key) are looked up)
	acct, err := client.Register(ctx, &acme.Account{Contact: cfg.Contact}, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		acct, err = client.GetReg(ctx, "")
	}
	if err != nil {
		return nil, fmt.Errorf("registering upstream account: %w", err)
	}

	return &UpstreamIssuer{
		client:     client,
		AccountURL: acct.URI,
		Directory:  dir,
	}, nil
}

func (u *UpstreamIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) ([]byte, error) {
	ids := make([]acme.AuthzID, 0, len(csr.DNSNames))
	for _, name := range csr.DNSNames {
		ids = append(ids, acme.AuthzID{Type: "dns", Value: name})
	}

	order, err := u.client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("creating upstream order: %w", err)
	}
	log.Printf("Created upstream order %s for %v", order.URI, csr.DNSNames)

	var pending []string
	for _, authzURL := range order.AuthzURLs {
		authz, err := u.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("fetching upstream authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		types := make([]string, 0, len(authz.Challenges))
		for _, ch := range authz.Challenges {
			types = append(types, ch.Type)
		}
		pending = append(pending, fmt.Sprintf("%s (%s)", authz.Identifier.Value, strings.Join(types, ", ")))
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("upstream validation not supported yet, pending authorizations: %s",
			strings.Join(pending, "; "))
	}

	der, _, err := u.client.CreateOrderCert(ctx, order.FinalizeURL, csr.Raw, true)
	if err != nil {
		return nil, fmt.Errorf("finalizing upstream order: %w", err)
	}

	var chain bytes.Buffer
	for _, c := range der {
		pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	return chain.Bytes(), nil
}
