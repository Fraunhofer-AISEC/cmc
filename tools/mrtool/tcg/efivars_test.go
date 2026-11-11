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

package tcg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestCert(t *testing.T, cn string) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// createSignatureList builds an EFI_SIGNATURE_LIST with equally sized entries
func createSignatureList(owner [16]byte, entries ...[]byte) []byte {
	sigSize := 16 + len(entries[0])
	b := make([]byte, 16)
	b = binary.LittleEndian.AppendUint32(b, uint32(SignatureListHeaderSize+len(entries)*sigSize))
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(sigSize))
	for _, e := range entries {
		b = append(b, owner[:]...)
		b = append(b, e...)
	}
	return b
}

func TestMeasureAuthorities(t *testing.T) {
	dir := t.TempDir()
	owner := [16]byte{0xbd, 0x9a, 0xfa, 0x77}

	cert1 := createTestCert(t, "Cert 1")
	cert2 := createTestCert(t, "Cert 2")
	other := createTestCert(t, "Other")

	// efivars format: 4-byte attributes, a SHA-256 list and two X.509 lists
	db := []byte{0x27, 0, 0, 0}
	db = append(db, createSignatureList(owner, make([]byte, 32), bytes.Repeat([]byte{1}, 32))...)
	db = append(db, createSignatureList(owner, cert1)...)
	db = append(db, createSignatureList(owner, cert2)...)

	dbPath := filepath.Join(dir, "db")
	if err := os.WriteFile(dbPath, db, 0644); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert2.der")
	if err := os.WriteFile(certPath, cert2, 0644); err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(dir, "other.der")
	if err := os.WriteFile(otherPath, other, 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := ParseSignatureLists(db[4:])
	if err != nil {
		t.Fatalf("ParseSignatureLists() error = %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("ParseSignatureLists() got %d entries, want 4", len(entries))
	}

	// UEFI_VARIABLE_DATA{EFI_IMAGE_SECURITY_DATABASE_GUID, "db", EFI_SIGNATURE_DATA}
	varData := append([]byte{}, EfiImageSecurityDatabaseGuid[:]...)
	varData = binary.LittleEndian.AppendUint64(varData, 2)
	varData = binary.LittleEndian.AppendUint64(varData, uint64(16+len(cert2)))
	varData = append(varData, 'd', 0, 'b', 0)
	varData = append(varData, owner[:]...)
	varData = append(varData, cert2...)
	eventDigest := sha256.Sum256(varData)
	want := sha256.Sum256(append(make([]byte, 32), eventDigest[:]...))

	digest, refvals, err := MeasureAuthorities(crypto.SHA256, TPM, make([]byte, 32), nil, 7,
		"db", EfiImageSecurityDatabaseGuid, dbPath, []string{certPath})
	if err != nil {
		t.Fatalf("MeasureAuthorities() error = %v", err)
	}
	if !bytes.Equal(digest, want[:]) {
		t.Errorf("MeasureAuthorities() digest = %x, want %x", digest, want)
	}
	if len(refvals) != 1 || !bytes.Equal(refvals[0].Hashes[0].Content, eventDigest[:]) {
		t.Errorf("MeasureAuthorities() unexpected reference values %v", refvals)
	}

	_, _, err = MeasureAuthorities(crypto.SHA256, TPM, make([]byte, 32), nil, 7,
		"db", EfiImageSecurityDatabaseGuid, dbPath, []string{otherPath})
	if err == nil {
		t.Errorf("MeasureAuthorities() expected error for certificate not in db")
	}
}
