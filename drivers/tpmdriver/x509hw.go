// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2023 Fraunhofer AISEC
// This is a heavily stripped and modified version of crypto/x509
// just for generating a certificate signing request with a custom
// hash function. This is required to sign a CSR with a restricted
// TPM key, which requires hashing inside the TPM to ensure that
// the to-be-signed data does NOT have the flag TPM_GENERATED_VALUE
// indicating that the data was from inside the TPM

package tpmdriver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	// Explicitly import these for their crypto.RegisterHash init side-effects.
	// Keep these as blank imports, even if they're imported above.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/google/go-attestation/attest"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// From crypto/x509/oid.go
// An OID represents an ASN.1 OBJECT IDENTIFIER.
type OID struct {
	der []byte
}

// From crypto/x509/oid.go
// String returns the string representation of the Object Identifier.
func (oid OID) String() string {
	var b strings.Builder
	b.Grow(32)
	const (
		valSize         = 64 // size in bits of val.
		bitsPerByte     = 7
		maxValSafeShift = (1 << (valSize - bitsPerByte)) - 1
	)
	var (
		start    = 0
		val      = uint64(0)
		numBuf   = make([]byte, 0, 21)
		bigVal   *big.Int
		overflow bool
	)
	for i, v := range oid.der {
		curVal := v & 0x7F
		valEnd := v&0x80 == 0
		if valEnd {
			if start != 0 {
				b.WriteByte('.')
			}
		}
		if !overflow && val > maxValSafeShift {
			if bigVal == nil {
				bigVal = new(big.Int)
			}
			bigVal = bigVal.SetUint64(val)
			overflow = true
		}
		if overflow {
			bigVal = bigVal.Lsh(bigVal, bitsPerByte).Or(bigVal, big.NewInt(int64(curVal)))
			if valEnd {
				if start == 0 {
					b.WriteString("2.")
					bigVal = bigVal.Sub(bigVal, big.NewInt(80))
				}
				numBuf = bigVal.Append(numBuf, 10)
				b.Write(numBuf)
				numBuf = numBuf[:0]
				val = 0
				start = i + 1
				overflow = false
			}
			continue
		}
		val <<= bitsPerByte
		val |= uint64(curVal)
		if valEnd {
			if start == 0 {
				if val < 80 {
					b.Write(strconv.AppendUint(numBuf, val/40, 10))
					b.WriteByte('.')
					b.Write(strconv.AppendUint(numBuf, val%40, 10))
				} else {
					b.WriteString("2.")
					b.Write(strconv.AppendUint(numBuf, val-80, 10))
				}
			} else {
				b.Write(strconv.AppendUint(numBuf, val, 10))
			}
			val = 0
			start = i + 1
		}
	}
	return b.String()
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

func marshalPublicKey(pub any) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		//lint:ignore SA1019 update as soon as upstream is updated
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: invalid elliptic curve public key")
		}
		//lint:ignore SA1019 update as soon as upstream is updated
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519
	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}
type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// Use function instead of method because we cannot define additional
// methods for x509.SignatureAlgorithm
func isRSAPSS(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

// OIDs for signature algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
//	md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
//	md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
//	sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
//	dsaWithSha1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) ansi-x962(10045)
//		signatures(4) ecdsa-with-SHA1(1)}
//
// RFC 4055 5 PKCS #1 Version 1.5
//
//	sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
//	sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
//	sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
// RFC 5758 3.1 DSA Signature Algorithms
//
//	dsaWithSha256 OBJECT IDENTIFIER ::= {
//		joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//		csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
//	ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
//	ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
	{x509.PureEd25519, "Ed25519", oidSignatureEd25519, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

// hashToPSSParameters contains the DER encoded RSA PSS parameters for the
// SHA256, SHA384, and SHA512 hashes as defined in RFC 3447, Appendix A.2.3.
// The parameters contain the following values:
//   - hashAlgorithm contains the associated hash identifier with NULL parameters
//   - maskGenAlgorithm always contains the default mgf1SHA1 identifier
//   - saltLength contains the length of the associated hash
//   - trailerField always contains the default trailerFieldBC value
var hashToPSSParameters = map[crypto.Hash]asn1.RawValue{
	crypto.SHA256: {FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162, 3, 2, 1, 32}},
	crypto.SHA384: {FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162, 3, 2, 1, 48}},
	crypto.SHA512: {FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162, 3, 2, 1, 64}},
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	if ai.Algorithm.Equal(oidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return x509.UnknownSignatureAlgorithm
		}
	}

	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return x509.UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return x509.UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(oidSHA256) && params.SaltLength == 32:
		return x509.SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA384) && params.SaltLength == 48:
		return x509.SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA512) && params.SaltLength == 64:
		return x509.SHA512WithRSAPSS
	}

	return x509.UnknownSignatureAlgorithm
}

// RFC 3279, 2.3 Public Key Algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
//	id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
//	id-ecPublicKey OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyEd25519 = oidSignatureEd25519
)

// getPublicKeyAlgorithmFromOID returns the exposed PublicKeyAlgorithm
// identifier for public key types supported in certificates and CSRs. Marshal
// and Parse functions may support a different set of public key types.
func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return x509.RSA
	case oid.Equal(oidPublicKeyDSA):
		return x509.DSA
	case oid.Equal(oidPublicKeyECDSA):
		return x509.ECDSA
	case oid.Equal(oidPublicKeyEd25519):
		return x509.Ed25519
	}
	return x509.UnknownPublicKeyAlgorithm
}

// RFC 5480, 2.1.1.1. Named Curve
//
//	secp224r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
//	secp256r1 OBJECT IDENTIFIER ::= {
//	  iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//	  prime(1) 7 }
//
//	secp384r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
//	secp521r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

// RFC 5280, 4.2.1.12  Extended Key Usage
//
//	anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
//	id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
//	id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
//	id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
//	id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
//	id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
//	id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
//	id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func oidFromExtKeyUsage(eku x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

// An InsecureAlgorithmError indicates that the SignatureAlgorithm used to
// generate the signature is not secure, and the signature has been rejected.
//
// To temporarily restore support for SHA-1 signatures, include the value
// "x509sha1=1" in the GODEBUG environment variable. Note that this option will
// be removed in a future release.
// type InsecureAlgorithmError SignatureAlgorithm

// func (e InsecureAlgorithmError) Error() string {
// 	var override string
// 	if SignatureAlgorithm(e) == SHA1WithRSA || SignatureAlgorithm(e) == ECDSAWithSHA1 {
// 		override = " (temporarily override with GODEBUG=x509sha1=1)"
// 	}
// 	return fmt.Sprintf("x509: cannot verify signature: insecure algorithm %v", SignatureAlgorithm(e)) + override
// }

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo x509.PublicKeyAlgorithm, pubKey any) error {
	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", expectedPubKeyAlgo.String(), pubKey)
}

// checkSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo x509.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey, allowSHA1 bool) (err error) {
	var hashType crypto.Hash
	var pubKeyAlgo x509.PublicKeyAlgorithm

	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
			break
		}
	}

	switch hashType {
	case crypto.Hash(0):
		if pubKeyAlgo != x509.Ed25519 {
			return ErrUnsupportedAlgorithm
		}
	case crypto.MD5:
		return x509.InsecureAlgorithmError(algo)
	case crypto.SHA1:
		// SHA-1 signatures are mostly disabled. See go.dev/issue/41682.
		if !allowSHA1 {
			return x509.InsecureAlgorithmError(algo)
		}
		fallthrough
	default:
		if !hashType.Available() {
			return ErrUnsupportedAlgorithm
		}
		h := hashType.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if pubKeyAlgo != x509.RSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if isRSAPSS(algo) {
			return rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		}
	case *ecdsa.PublicKey:
		if pubKeyAlgo != x509.ECDSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !ecdsa.VerifyASN1(pub, signed, signature) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	case ed25519.PublicKey:
		if pubKeyAlgo != x509.Ed25519 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return errors.New("x509: Ed25519 verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}

type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// oidNotInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		if err := isIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func buildCertExtensions(template *x509.Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalExtKeyUsage(template.ExtKeyUsage, template.UnknownExtKeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		ret[n], err = marshalBasicConstraints(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(subjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(subjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(authorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		// From RFC 5280, Section 4.2.1.6:
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.PolicyIdentifiers) > 0 || len(template.Policies) > 0) &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n], err = marshalCertificatePolicies(template.Policies, template.PolicyIdentifiers)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function and the list of
	// template fields used in CreateCertificate documentation.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func marshalKeyUsage(ku x509.KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	return ext, err
}

func marshalExtKeyUsage(extUsages []x509.ExtKeyUsage, unknownUsages []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionExtendedKeyUsage}

	oids := make([]asn1.ObjectIdentifier, len(extUsages)+len(unknownUsages))
	for i, u := range extUsages {
		if oid, ok := oidFromExtKeyUsage(u); ok {
			oids[i] = oid
		} else {
			return ext, errors.New("x509: unknown extended key usage")
		}
	}

	copy(oids[len(extUsages):], unknownUsages)

	var err error
	ext.Value, err = asn1.Marshal(oids)
	return ext, err
}

func marshalBasicConstraints(isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true}
	// Leaving MaxPathLen as zero indicates that no maximum path
	// length is desired, unless MaxPathLenZero is set. A value of
	// -1 causes encoding/asn1 to omit the value as desired.
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}
	var err error
	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLen})
	return ext, err
}

func marshalCertificatePolicies(policies []x509.OID, policyIdentifiers []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionCertificatePolicies}

	b := cryptobyte.NewBuilder(make([]byte, 0, 128))
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(child *cryptobyte.Builder) {
		// added is used to track OIDs which are duplicated in both Policies and PolicyIdentifiers
		// so they can be skipped. Note that this explicitly doesn't check for duplicate OIDs in
		// Policies or in PolicyIdentifiers themselves, as this would be considered breaking behavior.
		added := map[string]bool{}
		if len(policies) > 0 {
			log.Warnf("x509.OID policies are not supported for hardware-backed certs")
		}
		for _, v := range policyIdentifiers {
			if added[v.String()] {
				continue
			}
			child.AddASN1(cryptobyte_asn1.SEQUENCE, func(child *cryptobyte.Builder) {
				child.AddASN1ObjectIdentifier(v)
			})
		}
	})

	var err error
	ext.Value, err = b.Bytes()
	return ext, err
}

func buildCSRExtensions(template *x509.CertificateRequest) ([]pkix.Extension, error) {
	var ret []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		ret = append(ret, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	return append(ret, template.ExtraExtensions...), nil
}

func subjectBytes(cert *x509.Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// signingParamsForPublicKey returns the parameters to use for signing with
// priv. If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signingParamsForPublicKey(pub any, requestedSigAlgo x509.SignatureAlgorithm) (hashFunc crypto.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType x509.PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		hashFunc = crypto.SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	case ed25519.PublicKey:
		pubType = x509.Ed25519
		sigAlgo.Algorithm = oidSignatureEd25519

	default:
		err = errors.New("x509: only RSA, ECDSA and Ed25519 keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 && pubType != x509.Ed25519 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			if hashFunc == crypto.MD5 {
				err = errors.New("x509: signing with MD5 is not supported")
				return
			}
			if requestedSigAlgo == x509.SHA256WithRSAPSS ||
				requestedSigAlgo == x509.SHA384WithRSAPSS ||
				requestedSigAlgo == x509.SHA512WithRSAPSS {
				sigAlgo.Parameters = hashToPSSParameters[hashFunc]
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// CreateCertificate creates a new X.509 v3 certificate based on a template.
// The following members of template are currently used:
//
//   - AuthorityKeyId
//   - BasicConstraintsValid
//   - CRLDistributionPoints
//   - DNSNames
//   - EmailAddresses
//   - ExcludedDNSDomains
//   - ExcludedEmailAddresses
//   - ExcludedIPRanges
//   - ExcludedURIDomains
//   - ExtKeyUsage
//   - ExtraExtensions
//   - IPAddresses
//   - IsCA
//   - IssuingCertificateURL
//   - KeyUsage
//   - MaxPathLen
//   - MaxPathLenZero
//   - NotAfter
//   - NotBefore
//   - OCSPServer
//   - PermittedDNSDomains
//   - PermittedDNSDomainsCritical
//   - PermittedEmailAddresses
//   - PermittedIPRanges
//   - PermittedURIDomains
//   - PolicyIdentifiers
//   - Policies
//   - SerialNumber
//   - SignatureAlgorithm
//   - Subject
//   - SubjectKeyId
//   - URIs
//   - UnknownExtKeyUsage
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// certificate to be generated and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// The currently supported key types are *rsa.PublicKey, *ecdsa.PublicKey and
// ed25519.PublicKey. pub must be a supported key type, and priv must be a
// crypto.Signer with a supported public key.
//
// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
//
// If SubjectKeyId from template is empty and the template is a CA, SubjectKeyId
// will be generated from the hash of the public key.
//
// If both PolicyIdentifiers and Policies are populated, any OID which appears
// in both slices will only be added to the certificate policies extension once.
//
// This is a modified version of x509.CreateCertificate which does not perform
// hashing and can therefore be used to create certificates signed by restricted
// TPM keys.
func CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub any, priv *attest.AK, tpm *attest.TPM) ([]byte, error) {

	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	// RFC 5280 Section 4.1.2.2: serial number must positive
	//
	// We _should_ also restrict serials to <= 20 octets, but it turns out a lot of people
	// get this wrong, in part because the encoding can itself alter the length of the
	// serial. For now we accept these non-conformant serials.
	if template.SerialNumber.Sign() == -1 {
		return nil, errors.New("x509: serial number must be positive")
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if getPublicKeyAlgorithmFromOID(publicKeyAlgorithm.Algorithm) == x509.UnknownPublicKeyAlgorithm {
		return nil, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(publicKeyBytes)
		subjectKeyId = h[:]
	}

	// Check that the signer's public key matches the parent's public key, if available.
	type publicKey interface {
		Equal(crypto.PublicKey) bool
	}
	if akPub, ok := priv.Public().(publicKey); !ok {
		return nil, errors.New("x509: internal error: AK public key does not implement Equal")
	} else if parent.PublicKey != nil && !akPub.Equal(parent.PublicKey) {
		return nil, errors.New("x509: AK public key does not match parent's PublicKey")
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents

	signed := tbsCertContents

	// Usually, here the certificate is hashed and the digest (variable signed) is
	// passed to key.Sign()
	// However, for restricted TPM keys the hashing must be performed within
	// the TPM and therefore we do not hash here, but within SignMsg which
	// also performs signing within the TPM
	signature, err := priv.SignMsg(tpm, signed, hashFunc)
	if err != nil {
		return nil, err
	}

	signedCert, err := asn1.Marshal(certificate{
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, err
	}

	// Check the signature to ensure the TPM behaved correctly.
	if err := checkSignature(getSignatureAlgorithmFromAI(signatureAlgorithm), c.Raw, signature, priv.Public(), true); err != nil {
		return nil, fmt.Errorf("x509: signature over certificate returned by TPM is invalid: %w", err)
	}

	return signedCert, nil
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS #9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// CreateCertificateRequest creates a new certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//   - DNSNames
//   - EmailAddresses
//   - IPAddresses
//   - URIs
//   - ExtraExtensions
//   - Attributes (deprecated)
//
// priv is the private key to sign the CSR with, and the corresponding public
// key will be included in the CSR. It must implement crypto.Signer and its
// Public() method must return a *rsa.PublicKey or a *ecdsa.PublicKey or a
// ed25519.PublicKey. (A *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey satisfies this.)
//
// The returned slice is the certificate request in DER encoding.
//
// This is a modified version of x509.CreateCertificateRequest which does not
// perform hashing and can therefore be used to create CSRs for restricted TPM keys
func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv *attest.AK, tpm *attest.TPM) (csr []byte, err error) {

	var hashFunc crypto.Hash
	var sigAlgo pkix.AlgorithmIdentifier
	hashFunc, sigAlgo, err = signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	extensions, err := buildCSRExtensions(template)
	if err != nil {
		return nil, err
	}

	// Make a copy of template.Attributes because we may alter it below.
	//lint:ignore SA1019 as crypto/x509 still supports attributes
	attributes := make([]pkix.AttributeTypeAndValueSET, 0, len(template.Attributes))
	//lint:ignore SA1019 as crypto/x509 still supports attributes
	for _, attr := range template.Attributes {
		values := make([][]pkix.AttributeTypeAndValue, len(attr.Value))
		copy(values, attr.Value)
		attributes = append(attributes, pkix.AttributeTypeAndValueSET{
			Type:  attr.Type,
			Value: values,
		})
	}

	extensionsAppended := false
	if len(extensions) > 0 {
		// Append the extensions to an existing attribute if possible.
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			// specifiedExtensions contains all the extensions that we
			// found specified via template.Attributes.
			specifiedExtensions := make(map[string]bool)

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}

			newValue := make([]pkix.AttributeTypeAndValue, 0, len(atvSet.Value[0])+len(extensions))
			newValue = append(newValue, atvSet.Value[0]...)

			for _, e := range extensions {
				if specifiedExtensions[e.Id.String()] {
					// Attributes already contained a value for
					// this extension and it takes priority.
					continue
				}

				newValue = append(newValue, pkix.AttributeTypeAndValue{
					// There is no place for the critical
					// flag in an AttributeTypeAndValue.
					Type:  e.Id,
					Value: e.Value,
				})
			}

			atvSet.Value[0] = newValue
			extensionsAppended = true
			break
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return
	}

	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 && !extensionsAppended {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}

		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, errors.New("x509: failed to serialise extensions attribute: " + err.Error())
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}

		rawAttributes = append(rawAttributes, rawValue)
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	signed := tbsCSRContents

	// Usually, here the CSR is hashed and the digest (variable signed) is
	// passed to key.Sign()
	// However, for restricted TPM keys the hashing must be performed within
	// the TPM and therefore we do not hash here, but within SignMsg which
	// also performs signing within the TPM
	signature, err := priv.SignMsg(tpm, signed, hashFunc)
	if err != nil {
		return
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}
