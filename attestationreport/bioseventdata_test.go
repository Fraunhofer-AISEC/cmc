package attestationreport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

var efiCertX509Guid = []byte{
	0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
	0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
}

// uefiVariableData wraps a signature database into a UEFI_VARIABLE_DATA event
func uefiVariableData(name string, data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(make([]byte, 16)) // VariableName GUID
	binary.Write(buf, binary.LittleEndian, uint64(len(name)))
	binary.Write(buf, binary.LittleEndian, uint64(len(data)))
	for _, r := range name {
		binary.Write(buf, binary.LittleEndian, uint16(r))
	}
	buf.Write(data)
	return buf.Bytes()
}

// signatureList builds an EFI_SIGNATURE_LIST with one signature per entry
func signatureList(typeGuid []byte, sigs [][]byte) []byte {
	body := new(bytes.Buffer)
	sigSize := 0
	for _, s := range sigs {
		body.Write(make([]byte, 16)) // SignatureOwner GUID
		body.Write(s)
		sigSize = 16 + len(s)
	}

	buf := new(bytes.Buffer)
	buf.Write(typeGuid)
	binary.Write(buf, binary.LittleEndian, uint32(28+body.Len())) // SignatureListSize
	binary.Write(buf, binary.LittleEndian, uint32(0))             // SignatureHeaderSize
	binary.Write(buf, binary.LittleEndian, uint32(sigSize))       // SignatureSize
	buf.Write(body.Bytes())
	return buf.Bytes()
}

func testCert(t *testing.T, cn string) []byte {
	t.Helper()
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

// Reproduces the AWS vTPM eventlog panic: an EFI_CERT_X509_GUID signature list
// whose signature entry carries no certificate data
func TestParseEventDataEmptyX509Signature(t *testing.T) {
	db := signatureList(efiCertX509Guid, [][]byte{{}})
	event := uefiVariableData("db", db)

	if len(event) != 80 {
		t.Fatalf("unexpected test input length %v", len(event))
	}

	data := ParseEventData(event, "EV_EFI_VARIABLE_DRIVER_CONFIG")
	if data == nil || data.Uefivariabledata == nil {
		t.Fatal("expected UEFI variable data")
	}
	if len(data.Uefivariabledata.Signaturedb) != 1 {
		t.Fatalf("expected 1 signature list, got %v", len(data.Uefivariabledata.Signaturedb))
	}
	if len(data.Uefivariabledata.Signaturedb[0].Certificates) != 0 {
		t.Fatal("expected no parsed certificates")
	}
}

// Certificates must still be extracted, also from multiple signature lists
func TestParseEventDataX509Signatures(t *testing.T) {
	db := signatureList(efiCertX509Guid, [][]byte{testCert(t, "cert-a")})
	db = append(db, signatureList(efiCertX509Guid, [][]byte{testCert(t, "cert-b")})...)
	event := uefiVariableData("db", db)

	data := ParseEventData(event, "EV_EFI_VARIABLE_DRIVER_CONFIG")
	if data == nil || data.Uefivariabledata == nil {
		t.Fatal("expected UEFI variable data")
	}
	sigdbs := data.Uefivariabledata.Signaturedb
	if len(sigdbs) != 2 {
		t.Fatalf("expected 2 signature lists, got %v", len(sigdbs))
	}
	for i, cn := range []string{"cert-a", "cert-b"} {
		if len(sigdbs[i].Certificates) != 1 {
			t.Fatalf("expected 1 certificate in list %v, got %v", i, len(sigdbs[i].Certificates))
		}
		if got := sigdbs[i].Certificates[0].Certificates.Subject.CommonName; got != cn {
			t.Fatalf("expected CN %v, got %v", cn, got)
		}
	}
}

// A signature list with multiple SHA-256 hashes must be parsed completely
func TestParseEventDataSha256Signatures(t *testing.T) {
	sha256Guid := []byte{
		0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
		0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
	}
	db := signatureList(sha256Guid, [][]byte{
		bytes.Repeat([]byte{0xaa}, 32),
		bytes.Repeat([]byte{0xbb}, 32),
	})
	event := uefiVariableData("dbx", db)

	data := ParseEventData(event, "EV_EFI_VARIABLE_DRIVER_CONFIG")
	if data == nil || data.Uefivariabledata == nil {
		t.Fatal("expected UEFI variable data")
	}
	sigdbs := data.Uefivariabledata.Signaturedb
	if len(sigdbs) != 1 {
		t.Fatalf("expected 1 signature list, got %v", len(sigdbs))
	}
	if len(sigdbs[0].Sha256Hash) != 2 {
		t.Fatalf("expected 2 hashes, got %v", len(sigdbs[0].Sha256Hash))
	}
	if !bytes.Equal(sigdbs[0].Sha256Hash[1].Hash, bytes.Repeat([]byte{0xbb}, 32)) {
		t.Fatalf("unexpected hash %x", sigdbs[0].Sha256Hash[1].Hash)
	}
}
