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

package est

// Attestation in PKCS#10 CSRs as specified by draft-ietf-lamps-csr-attestation-33. The CSR carries
// an id-aa-attestation attribute with an AttestationBundle:
//
//	AttestationBundle ::= SEQUENCE {
//	   attestations SEQUENCE SIZE (1..MAX) OF AttestationStatement,
//	   certs SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL }
//
//	AttestationStatement ::= SEQUENCE { type OBJECT IDENTIFIER, stmt ANY DEFINED BY type }
//
// Supported statements:
//   - TPM key certification (TCG tcg-attest-tpm-certify), the AK certificate is carried in certs
//   - CMC attestation report as CMW record (RFC 9999, id-pe-cmw)
//
// Unknown statement types, CMW types and certificate formats are ignored.

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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// OidAttestation is id-aa-attestation { id-aa 59 }
	OidAttestation = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 59}
	// OidTpmCertify is tcg-attest-tpm-certify { 2 23 133 20 1 }
	OidTpmCertify = asn1.ObjectIdentifier{2, 23, 133, 20, 1}
	// OidCmw is id-pe-cmw { id-pe 35 }
	OidCmw = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 35}

	oidExtensionRequest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidExtensionSubjectAltNm = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSha256WithRsa         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidEcdsaWithSha256       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidEcdsaWithSha384       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidEcdsaWithSha512       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519               = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// CMW media types of the CMC attestation report
const (
	MediaTypeCmcReportJson = "application/vnd.cmc.attestation-report+json"
	MediaTypeCmcReportCbor = "application/vnd.cmc.attestation-report+cbor"
)

// CsrAttestation holds the attestation statements and certificates of a CSR
type CsrAttestation struct {
	// TpmCertify is the TPM2_Certify of the CSR key by the AK. CreateData is not transmitted.
	TpmCertify *attest.CertificationParameters
	// Report is the serialized CMC attestation report
	Report []byte
	// Certs holds the certificates to verify the statements, e.g. the AK chain, in no
	// specific order
	Certs []*x509.Certificate
}

// CreateCsr creates a PKCS#10 CSR, which carries the attestation att if not nil. Go's
// x509.CreateCertificateRequest cannot encode arbitrary attributes, therefore the CSR is built
// manually. Supports RSA (PKCS#1 v1.5 with SHA-256), ECDSA (P-256, P-384, P-521) and Ed25519 keys.
func CreateCsr(signer crypto.Signer, subject pkix.Name, dnsNames []string, ips []net.IP,
	att *CsrAttestation,
) (*x509.CertificateRequest, error) {

	opts, sigAlg, err := signingParams(signer.Public())
	if err != nil {
		return nil, err
	}

	rawSubject, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	var attrs [][]byte
	if len(dnsNames) > 0 || len(ips) > 0 {
		attr, err := marshalSanRequest(dnsNames, ips)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	if att != nil {
		bundle, err := marshalAttestationBundle(att)
		if err != nil {
			return nil, err
		}
		attr, err := marshalAttribute(OidAttestation, bundle)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}

	tbs, err := marshalTbsCsr(rawSubject, spki, attrs)
	if err != nil {
		return nil, err
	}

	sig, err := crypto.SignMessage(signer, rand.Reader, tbs, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(sig)
	})
	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %w", err)
	}

	return csr, nil
}

// ParseCsrAttestation parses the attestation attribute of the CSR. It returns nil if the CSR
// carries no attestation. The CSR signature must have been verified before.
func ParseCsrAttestation(csr *x509.CertificateRequest) (*CsrAttestation, error) {

	input := cryptobyte.String(csr.RawTBSCertificateRequest)
	var tbs, attrs cryptobyte.String
	var hasAttrs bool
	if !input.ReadASN1(&tbs, cbasn1.SEQUENCE) || !input.Empty() ||
		!tbs.SkipASN1(cbasn1.INTEGER) ||
		!tbs.SkipASN1(cbasn1.SEQUENCE) ||
		!tbs.SkipASN1(cbasn1.SEQUENCE) ||
		!tbs.ReadOptionalASN1(&attrs, &hasAttrs, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.Empty() {
		return nil, errors.New("malformed CSR")
	}

	var bundle cryptobyte.String
	found := false
	for !attrs.Empty() {
		var attr, values cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !attrs.ReadASN1(&attr, cbasn1.SEQUENCE) ||
			!attr.ReadASN1ObjectIdentifier(&oid) ||
			!attr.ReadASN1(&values, cbasn1.SET) ||
			!attr.Empty() {
			return nil, errors.New("malformed CSR attribute")
		}
		if !oid.Equal(OidAttestation) {
			continue
		}
		if found {
			return nil, errors.New("CSR contains multiple attestation attributes")
		}
		found = true
		if !values.ReadASN1(&bundle, cbasn1.SEQUENCE) || !values.Empty() {
			return nil, errors.New("attestation attribute must contain exactly one bundle")
		}
	}
	if !found {
		return nil, nil
	}

	return parseAttestationBundle(bundle)
}

func parseAttestationBundle(bundle cryptobyte.String) (*CsrAttestation, error) {

	var stmts, certs cryptobyte.String
	var hasCerts bool
	if !bundle.ReadASN1(&stmts, cbasn1.SEQUENCE) ||
		!bundle.ReadOptionalASN1(&certs, &hasCerts, cbasn1.SEQUENCE) ||
		!bundle.Empty() {
		return nil, errors.New("malformed attestation bundle")
	}
	if stmts.Empty() {
		return nil, errors.New("attestation bundle contains no statements")
	}
	if hasCerts && certs.Empty() {
		return nil, errors.New("attestation bundle contains empty certs")
	}

	att := &CsrAttestation{}

	for !stmts.Empty() {
		var stmt, value cryptobyte.String
		var typ asn1.ObjectIdentifier
		var tag cbasn1.Tag
		if !stmts.ReadASN1(&stmt, cbasn1.SEQUENCE) ||
			!stmt.ReadASN1ObjectIdentifier(&typ) ||
			!stmt.ReadAnyASN1Element(&value, &tag) ||
			!stmt.Empty() {
			return nil, errors.New("malformed attestation statement")
		}

		switch {
		case typ.Equal(OidTpmCertify):
			if att.TpmCertify != nil {
				return nil, errors.New("multiple TPM certify statements")
			}
			params, err := parseTpmCertify(value)
			if err != nil {
				return nil, err
			}
			att.TpmCertify = params

		case typ.Equal(OidCmw):
			mediaType, data, err := parseCmwRecord(value, tag)
			if err != nil {
				return nil, err
			}
			if mediaType != MediaTypeCmcReportJson && mediaType != MediaTypeCmcReportCbor {
				log.Debugf("Ignoring CMW of type %q", mediaType)
				continue
			}
			if att.Report != nil {
				return nil, errors.New("multiple attestation report statements")
			}
			if len(data) == 0 {
				return nil, errors.New("empty attestation report")
			}
			att.Report = data

		default:
			log.Debugf("Ignoring attestation statement of type %v", typ)
		}
	}

	for !certs.Empty() {
		var raw cryptobyte.String
		var tag cbasn1.Tag
		if !certs.ReadAnyASN1Element(&raw, &tag) {
			return nil, errors.New("malformed attestation bundle certificate")
		}
		switch tag {
		case cbasn1.SEQUENCE:
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to parse attestation bundle certificate: %w", err)
			}
			att.Certs = append(att.Certs, cert)
		case cbasn1.Tag(3).Constructed().ContextSpecific():
			log.Debug("Ignoring attestation bundle certificate of other format")
		default:
			return nil, fmt.Errorf("invalid attestation bundle certificate choice %v", tag)
		}
	}

	return att, nil
}

// parseTpmCertify parses the TCG statement
//
//	Tcg-csr-tpm-certify ::= SEQUENCE {
//	  tpmSAttest OCTET STRING, signature OCTET STRING, tpmTPublic OCTET STRING OPTIONAL }
func parseTpmCertify(value cryptobyte.String) (*attest.CertificationParameters, error) {
	var seq, attestation, sig, public cryptobyte.String
	var hasPublic bool
	if !value.ReadASN1(&seq, cbasn1.SEQUENCE) ||
		!seq.ReadASN1(&attestation, cbasn1.OCTET_STRING) ||
		!seq.ReadASN1(&sig, cbasn1.OCTET_STRING) ||
		!seq.ReadOptionalASN1(&public, &hasPublic, cbasn1.OCTET_STRING) ||
		!seq.Empty() || !value.Empty() {
		return nil, errors.New("malformed TPM certify statement")
	}
	if len(attestation) == 0 || len(sig) == 0 || len(public) == 0 {
		return nil, errors.New("TPM certify statement must contain attestation, signature and public")
	}
	return &attest.CertificationParameters{
		Public:            bytes.Clone(public),
		CreateAttestation: bytes.Clone(attestation),
		CreateSignature:   bytes.Clone(sig),
	}, nil
}

// parseCmwRecord parses the CMW CHOICE { json UTF8String, cbor OCTET STRING } and returns media
// type and value of a record CMW. Collection and tag CMWs return an empty media type.
func parseCmwRecord(value cryptobyte.String, tag cbasn1.Tag) (string, []byte, error) {
	var content cryptobyte.String
	if !value.ReadASN1(&content, tag) || !value.Empty() {
		return "", nil, errors.New("malformed CMW")
	}
	if len(content) == 0 {
		return "", nil, errors.New("empty CMW")
	}

	switch tag {
	case cbasn1.UTF8String:
		if content[0] != '[' {
			return "", nil, nil
		}
		var record []json.RawMessage
		if err := json.Unmarshal(content, &record); err != nil {
			return "", nil, fmt.Errorf("malformed JSON CMW record: %w", err)
		}
		if len(record) != 2 && len(record) != 3 {
			return "", nil, fmt.Errorf("invalid JSON CMW record length %v", len(record))
		}
		var mediaType, encoded string
		if err := json.Unmarshal(record[0], &mediaType); err != nil {
			return "", nil, fmt.Errorf("invalid JSON CMW record type: %w", err)
		}
		if err := json.Unmarshal(record[1], &encoded); err != nil {
			return "", nil, fmt.Errorf("invalid JSON CMW record value: %w", err)
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return "", nil, fmt.Errorf("invalid JSON CMW record value encoding: %w", err)
		}
		return baseMediaType(mediaType), data, nil

	case cbasn1.OCTET_STRING:
		// CBOR array major type, other types are collections or tags
		if content[0]>>5 != 4 {
			return "", nil, nil
		}
		var record []cbor.RawMessage
		if err := cbor.Unmarshal(content, &record); err != nil {
			return "", nil, fmt.Errorf("malformed CBOR CMW record: %w", err)
		}
		if len(record) != 2 && len(record) != 3 {
			return "", nil, fmt.Errorf("invalid CBOR CMW record length %v", len(record))
		}
		var mediaType string
		if err := cbor.Unmarshal(record[0], &mediaType); err != nil {
			// CoAP content formats are not supported
			return "", nil, nil
		}
		var data []byte
		if err := cbor.Unmarshal(record[1], &data); err != nil {
			return "", nil, fmt.Errorf("invalid CBOR CMW record value: %w", err)
		}
		return baseMediaType(mediaType), data, nil

	default:
		return "", nil, fmt.Errorf("invalid CMW choice %v", tag)
	}
}

func baseMediaType(s string) string {
	t, _, err := mime.ParseMediaType(s)
	if err != nil {
		return s
	}
	return t
}

func marshalAttestationBundle(att *CsrAttestation) ([]byte, error) {

	var stmts [][]byte

	if att.TpmCertify != nil {
		p := att.TpmCertify
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OidTpmCertify)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(p.CreateAttestation)
				b.AddASN1OctetString(p.CreateSignature)
				b.AddASN1OctetString(p.Public)
			})
		})
		stmt, err := b.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TPM certify statement: %w", err)
		}
		stmts = append(stmts, stmt)
	}

	if att.Report != nil {
		stmt, err := marshalCmwReport(att.Report)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, stmt)
	}

	if len(stmts) == 0 {
		return nil, errors.New("attestation contains no statements")
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, stmt := range stmts {
				b.AddBytes(stmt)
			}
		})
		if len(att.Certs) > 0 {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, c := range att.Certs {
					b.AddBytes(c.Raw)
				}
			})
		}
	})
	return b.Bytes()
}

// marshalCmwReport wraps the report into a JSON or CBOR record CMW depending on its serialization
func marshalCmwReport(report []byte) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	if json.Valid(report) {
		record, err := json.Marshal([]string{
			MediaTypeCmcReportJson, base64.RawURLEncoding.EncodeToString(report)})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON CMW: %w", err)
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OidCmw)
			b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes(record) })
		})
	} else {
		record, err := cbor.Marshal([]any{MediaTypeCmcReportCbor, report})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CBOR CMW: %w", err)
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OidCmw)
			b.AddASN1OctetString(record)
		})
	}
	return b.Bytes()
}

// marshalSanRequest returns the extensionRequest attribute with the subject alternative names
func marshalSanRequest(dnsNames []string, ips []net.IP) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, name := range dnsNames {
			b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(name))
			})
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			b.AddASN1(cbasn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(ip)
			})
		}
	})
	san, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SANs: %w", err)
	}

	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidExtensionSubjectAltNm)
			b.AddASN1OctetString(san)
		})
	})
	exts, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal extension request: %w", err)
	}

	return marshalAttribute(oidExtensionRequest, exts)
}

func marshalAttribute(oid asn1.ObjectIdentifier, values ...[]byte) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			for _, v := range values {
				b.AddBytes(v)
			}
		})
	})
	return b.Bytes()
}

// marshalTbsCsr returns the CertificationRequestInfo. The attributes are sorted as required for
// a DER SET OF.
func marshalTbsCsr(rawSubject, spki []byte, attrs [][]byte) ([]byte, error) {
	attrs = slices.Clone(attrs)
	slices.SortFunc(attrs, bytes.Compare)

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddBytes(rawSubject)
		b.AddBytes(spki)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			for _, a := range attrs {
				b.AddBytes(a)
			}
		})
	})
	tbs, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR info: %w", err)
	}
	return tbs, nil
}

// signingParams returns the signer options and the DER encoded signature AlgorithmIdentifier
func signingParams(pub crypto.PublicKey) (crypto.SignerOpts, []byte, error) {
	var opts crypto.SignerOpts
	var oid asn1.ObjectIdentifier
	nullParams := false

	switch k := pub.(type) {
	case *rsa.PublicKey:
		opts, oid, nullParams = crypto.SHA256, oidSha256WithRsa, true
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			opts, oid = crypto.SHA256, oidEcdsaWithSha256
		case elliptic.P384():
			opts, oid = crypto.SHA384, oidEcdsaWithSha384
		case elliptic.P521():
			opts, oid = crypto.SHA512, oidEcdsaWithSha512
		default:
			return nil, nil, fmt.Errorf("unsupported curve %v", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		opts, oid = crypto.Hash(0), oidEd25519
	default:
		return nil, nil, fmt.Errorf("unsupported public key type %T", pub)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if nullParams {
			b.AddASN1NULL()
		}
	})
	algId, err := b.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal signature algorithm: %w", err)
	}
	return opts, algId, nil
}
