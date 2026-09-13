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

package internal

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// HashPair is a single RIM payload resource: the measurement index and the set of
// reference hashes considered valid for it.
type HashPair struct {
	Index   string
	Hashes  []string
	HashMap map[string]struct{}
	Active  bool
}

// RIM is a parsed and signature-verified reference integrity manifest.
type RIM struct {
	Name  string
	Pairs []HashPair
	Certs []*x509.Certificate
}

func (r RIM) String() string {
	if len(r.Pairs) == 0 {
		return "RIM: No pairs found."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("RIM (Total Pairs: %d):\n", len(r.Pairs)))
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	for _, pair := range r.Pairs {
		if !pair.Active {
			continue
		}
		hashList := strings.Join(pair.Hashes, ", ")
		sb.WriteString(fmt.Sprintf("  Index [%s] -> [%s]\n", pair.Index, hashList))
	}
	sb.WriteString(strings.Repeat("-", 40))

	return sb.String()
}

// ParseRIM parses the XML RIM, verifies its XML signature and anchors the embedded signing
// certificate chain in one of the RIM signing root CAs identified by caFingerprints, and
// returns the reference hashes found in the signed subtree.
func ParseRIM(xmlData []byte, name string, currentTime time.Time, caFingerprints []string,
) (RIM, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return RIM{}, err
	}

	validatedRoot, certs, err := validateRIM(doc, currentTime, caFingerprints)
	if err != nil {
		return RIM{}, err
	}

	var rim RIM
	rim.Certs = certs
	rim.Name = name

	// Fixes XSW: Evaluates relative to validatedRoot rather than structural-wide document traversal
	for _, resourceEl := range validatedRoot.FindElements(".//Resource") {
		index := resourceEl.SelectAttrValue("index", "")
		if index == "" {
			continue
		}

		var hashes []string
		var active bool

		for _, attr := range resourceEl.Attr {
			if strings.Contains(attr.Key, "Hash") {
				hashes = append(hashes, attr.Value)
			}
			if attr.Key == "active" {
				active = (attr.Value == "True")
			}
		}

		if len(hashes) > 0 {
			rim.Pairs = append(rim.Pairs, HashPair{
				Index:  index,
				Hashes: hashes,
				Active: active,
			})
		}
	}

	return rim, nil
}

// ExtractRimCerts returns the certificate chain embedded in the RIM's XML signature without
// verifying.
func ExtractRimCerts(xmlData []byte) ([]*x509.Certificate, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, err
	}
	return certsFromRim(doc)
}

// certsFromRim collects the certificates from the RIM's XML signature, leaf first.
// Unparsable entries are skipped
func certsFromRim(doc *etree.Document) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, certEl := range doc.FindElements("//X509Certificate") {
		base64Clean := cleanBase64String(certEl.Text())
		certBytes, err := base64.StdEncoding.DecodeString(base64Clean)
		if err != nil {
			continue
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("no valid certs in xml payload")
	}

	return certs, nil
}

// MergeRIMs unions the payload resources of multiple RIMs by measurement index. An
// active pair takes precedence over an inactive one; where two active pairs share an
// index, their hash sets are unioned.
func MergeRIMs(rims ...RIM) RIM {
	type entry struct {
		pair HashPair
	}

	seen := make(map[string]entry)

	for _, rim := range rims {
		for _, pair := range rim.Pairs {
			existing, exists := seen[pair.Index]
			if !exists {
				seen[pair.Index] = entry{pair: pair}
				continue
			}

			if pair.Active && !existing.pair.Active {
				seen[pair.Index] = entry{pair: pair}
			} else if pair.Active && existing.pair.Active {
				hashSet := make(map[string]struct{}, len(existing.pair.Hashes)+len(pair.Hashes))
				for _, h := range existing.pair.Hashes {
					hashSet[h] = struct{}{}
				}
				for _, h := range pair.Hashes {
					if _, dup := hashSet[h]; !dup {
						existing.pair.Hashes = append(existing.pair.Hashes, h)
					}
				}
				seen[pair.Index] = existing
			}
		}
	}

	var merged RIM
	type sortablePair struct {
		pair     HashPair
		intIndex int
	}

	sortList := make([]sortablePair, 0, len(seen))
	for _, e := range seen {
		val, _ := strconv.Atoi(e.pair.Index)
		sortList = append(sortList, sortablePair{pair: e.pair, intIndex: val})
	}

	sort.Slice(sortList, func(i, j int) bool {
		return sortList[i].intIndex < sortList[j].intIndex
	})

	merged.Pairs = make([]HashPair, len(sortList))
	for i, item := range sortList {
		merged.Pairs[i] = item.pair
	}
	for i := range merged.Pairs {
		merged.Pairs[i].HashMap = make(map[string]struct{}, len(merged.Pairs[i].Hashes))
		for _, h := range merged.Pairs[i].Hashes {
			merged.Pairs[i].HashMap[h] = struct{}{}
		}
	}

	return merged
}

// validateRIM verifies the enveloped XML signature and returns the signed subtree
// together with the certificate chain that signed it.
func validateRIM(doc *etree.Document, currentTime time.Time, caFingerprints []string,
) (*etree.Element, []*x509.Certificate, error) {
	sigValEl := doc.FindElement("//SignatureValue")
	if sigValEl == nil {
		sigValEl = doc.FindElement("//ds:SignatureValue")
	}
	if sigValEl == nil {
		return nil, nil, errors.New("no sigval element in xml")
	}

	cleanSigBase64 := cleanBase64String(sigValEl.Text())
	rawSigBytes, err := base64.StdEncoding.DecodeString(cleanSigBase64)
	if err != nil {
		return nil, nil, err
	}

	// NVIDIA emits the raw (r||s) form, goxmldsig expects ASN.1
	derSigBytes, err := convertFlatToDER(rawSigBytes)
	if err != nil {
		return nil, nil, err
	}

	sigValEl.SetText(base64.StdEncoding.EncodeToString(derSigBytes))

	certsInXML, err := certsFromRim(doc)
	if err != nil {
		return nil, nil, err
	}

	if _, ok := certsInXML[0].PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, nil, errors.New("no pub key in validation path context")
	}

	certStore := &dsig.MemoryX509CertificateStore{Roots: certsInXML}
	validator := dsig.NewDefaultValidationContext(certStore)

	// Fixes XSW: validatedRoot captures ONLY the inner signed tree
	validatedRoot, err := validator.Validate(doc.Root())
	if err != nil {
		return nil, nil, fmt.Errorf("xml signature validation failed: %w", err)
	}

	// The signature above only proves the document is self-consistent, as the signing chain
	// is embedded in the document itself. Anchor the chain in one of the RIM signing root
	// CAs pinned by the signed metadata before trusting its contents.
	root, err := SelfSignedRoot(certsInXML)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine RIM signing root: %w", err)
	}
	if _, err := MatchCaFingerprint(root, caFingerprints); err != nil {
		return nil, nil, fmt.Errorf("RIM signing root %q is not trusted: %w",
			root.Subject.CommonName, err)
	}

	leafCert := certsInXML[0]
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	intermediatePool := x509.NewCertPool()
	for _, c := range certsInXML[1:] {
		if c != nil {
			intermediatePool.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		CurrentTime:   currentTime,
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return nil, nil, err
	}

	return validatedRoot, certsInXML, nil
}

type dsigECDSASignature struct {
	R, S *big.Int
}

// convertFlatToDER converts a raw (r||s) ECDSA-P384 signature into its ASN.1 encoding
func convertFlatToDER(flatSig []byte) ([]byte, error) {
	if len(flatSig) != 96 {
		return nil, fmt.Errorf("expected 96-byte signature for ecdsa-sha384, got %d bytes", len(flatSig))
	}

	r := new(big.Int).SetBytes(flatSig[:48])
	s := new(big.Int).SetBytes(flatSig[48:])

	derSig, err := asn1.Marshal(dsigECDSASignature{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ASN.1 sequence: %w", err)
	}

	return derSig, nil
}

func cleanBase64String(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
