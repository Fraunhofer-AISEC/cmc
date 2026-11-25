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

package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/fxamacker/cbor/v2"
)

type testPki struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func newTestPki(t *testing.T) *testPki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPki{caKey: key, caCert: cert}
}

// issue returns the PEM encoded certificate chain for pub
func (p *testPki) issue(t *testing.T, pub crypto.PublicKey) [][]byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caCert.Raw}),
	}
}

type testKey struct {
	name string
	priv crypto.Signer
	pem  []byte
}

func newTestKey(t *testing.T, name string, priv crypto.Signer, pkcs8 bool) testKey {
	t.Helper()
	var block *pem.Block
	if ec, ok := priv.(*ecdsa.PrivateKey); ok && !pkcs8 {
		der, err := x509.MarshalECPrivateKey(ec)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	} else if r, ok := priv.(*rsa.PrivateKey); ok && !pkcs8 {
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r)}
	} else {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	return testKey{name: name, priv: priv, pem: pem.EncodeToMemory(block)}
}

func generateKeys(t *testing.T) map[string]testKey {
	t.Helper()
	keys := map[string]testKey{}
	for _, c := range []struct {
		name  string
		curve elliptic.Curve
	}{{"P-224", elliptic.P224()}, {"P-256", elliptic.P256()}, {"P-384", elliptic.P384()}, {"P-521", elliptic.P521()}} {
		k, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[c.name] = newTestKey(t, c.name, k, false)
		keys[c.name+"-PKCS8"] = newTestKey(t, c.name+"-PKCS8", k, true)
	}
	for _, bits := range []int{1024, 2048, 3072, 4096} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		name := "RSA-" + big.NewInt(int64(bits)).String()
		keys[name] = newTestKey(t, name, k, true)
		keys[name+"-PKCS1"] = newTestKey(t, name+"-PKCS1", k, false)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys["Ed25519"] = newTestKey(t, "Ed25519", ed, true)
	return keys
}

func testInputs(t *testing.T) map[string][]byte {
	t.Helper()
	c, err := cbor.Marshal(map[string]string{"type": "Test Manifest", "name": "test"})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"JSON": []byte(`{"type":"Test Manifest","name":"test"}`),
		"CBOR": c,
	}
}

func verify(t *testing.T, signed, data []byte, ca *x509.Certificate, numSigs int) {
	t.Helper()
	s, err := ar.DetectSerialization(signed)
	if err != nil {
		t.Fatalf("failed to detect serialization: %v", err)
	}
	payload, sigs, result := s.Verify(signed, []*x509.Certificate{ca})
	if result.Status != ar.StatusSuccess {
		t.Fatalf("verification failed: %+v, %+v", result, sigs)
	}
	if len(sigs) != numSigs {
		t.Fatalf("got %v signatures, want %v", len(sigs), numSigs)
	}
	if !bytes.Equal(payload, data) {
		t.Fatalf("payload mismatch")
	}
}

func TestSign(t *testing.T) {
	pki := newTestPki(t)
	keys := generateKeys(t)
	inputs := testInputs(t)

	tests := []struct {
		keys    []string
		format  string
		wantErr bool
	}{
		{[]string{"P-256"}, "JSON", false},
		{[]string{"P-256"}, "CBOR", false},
		{[]string{"P-256-PKCS8"}, "JSON", false},
		{[]string{"P-256-PKCS8"}, "CBOR", false},
		{[]string{"P-384"}, "JSON", false},
		{[]string{"P-384"}, "CBOR", false},
		{[]string{"P-521"}, "JSON", false},
		{[]string{"P-521"}, "CBOR", false},
		{[]string{"RSA-2048"}, "JSON", false},
		{[]string{"RSA-2048"}, "CBOR", false},
		{[]string{"RSA-2048-PKCS1"}, "JSON", false},
		{[]string{"RSA-2048-PKCS1"}, "CBOR", false},
		{[]string{"RSA-3072"}, "JSON", false},
		{[]string{"RSA-3072"}, "CBOR", false},
		{[]string{"RSA-4096"}, "JSON", false},
		{[]string{"RSA-4096"}, "CBOR", false},
		{[]string{"Ed25519"}, "JSON", false},
		{[]string{"Ed25519"}, "CBOR", false},
		{[]string{"P-256", "P-384", "Ed25519"}, "JSON", false},
		{[]string{"P-256", "P-384", "Ed25519"}, "CBOR", false},
		{[]string{"P-256", "RSA-2048"}, "JSON", false},
		{[]string{"P-256", "RSA-4096"}, "CBOR", false},
		// Unsupported key sizes and curves
		{[]string{"RSA-1024"}, "JSON", true},
		{[]string{"RSA-1024"}, "CBOR", true},
		{[]string{"P-224"}, "JSON", true},
		{[]string{"P-224"}, "CBOR", true},
	}

	for _, tt := range tests {
		name := tt.format
		for _, k := range tt.keys {
			name += "/" + k
		}
		t.Run(name, func(t *testing.T) {
			data := inputs[tt.format]
			keysPem := make([][]byte, 0)
			chainsPem := make([][][]byte, 0)
			for _, k := range tt.keys {
				keysPem = append(keysPem, keys[k].pem)
				chainsPem = append(chainsPem, pki.issue(t, keys[k].priv.Public()))
			}
			signed, err := Sign(data, keysPem, chainsPem)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Sign() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			verify(t, signed, data, pki.caCert, len(tt.keys))
		})
	}
}

func TestSignKeyMismatch(t *testing.T) {
	pki := newTestPki(t)
	keys := generateKeys(t)
	for format, data := range testInputs(t) {
		t.Run(format, func(t *testing.T) {
			// Key does not match leaf certificate
			_, err := Sign(data, [][]byte{keys["P-256"].pem},
				[][][]byte{pki.issue(t, keys["P-384"].priv.Public())})
			if err == nil {
				t.Fatal("expected error for mismatching key and certificate")
			}
			// Second chain belongs to the first key
			_, err = Sign(data, [][]byte{keys["P-256"].pem, keys["P-384"].pem},
				[][][]byte{pki.issue(t, keys["P-256"].priv.Public()), pki.issue(t, keys["P-256"].priv.Public())})
			if err == nil {
				t.Fatal("expected error for mismatching key and certificate")
			}
			// Number of keys and chains differ
			_, err = Sign(data, [][]byte{keys["P-256"].pem, keys["P-384"].pem},
				[][][]byte{pki.issue(t, keys["P-256"].priv.Public())})
			if err == nil {
				t.Fatal("expected error for differing number of keys and chains")
			}
		})
	}
}

// badSigner returns signatures from a different key
type badSigner struct {
	crypto.Signer
	other crypto.Signer
}

func (s badSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.other.Sign(r, digest, opts)
}

func TestSignVerifiesOutput(t *testing.T) {
	pki := newTestPki(t)
	keys := generateKeys(t)
	for format, data := range testInputs(t) {
		t.Run(format, func(t *testing.T) {
			k := keys["P-256"]
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(pki.issue(t, k.priv.Public())[0])
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			signer := badSigner{Signer: k.priv, other: other}
			_, err = signWith(data, []crypto.Signer{signer}, [][]*x509.Certificate{{leaf, pki.caCert}})
			if err == nil {
				t.Fatal("expected error for invalid signature")
			}
		})
	}
}
