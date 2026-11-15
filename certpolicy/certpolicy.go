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

// Package certpolicy defines the certificate policy OIDs (RFC 5280) the EST server puts into
// issued certificates to state how the key was enrolled, and checks them on peer certificates.
//
// This supports the RATS passport model: a relying party trusts a certificate issued after
// attestation without attesting the peer itself. All OIDs live below a configurable base arc:
//
//	<arc>.1.1      key enrolled with software-based attestation
//	<arc>.1.2      key enrolled with hardware-based attestation
//	<arc>.2.<n>    hardware trust anchor verified during enrollment (1 tpm, 2 snp, 3 tdx, 4 sgx)
//
// Keys enrolled without attestation carry no policy OID.
package certpolicy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// DefaultArc is a UUID-based OID (ITU-T X.667), which requires no registration. Production
// deployments can use an arc below their private enterprise number instead.
const DefaultArc = "2.25.130688535707081957510737207999343475614"

// teeArcs maps the hardware trust anchors to their sub-arc and the measurement result type
// that proves their verification.
var teeArcs = []struct {
	name   string
	arc    int
	result string
}{
	{"tpm", 1, ar.TYPE_RESULT_TPM},
	{"snp", 2, ar.TYPE_RESULT_SNP},
	{"tdx", 3, ar.TYPE_RESULT_TDX},
	{"sgx", 4, ar.TYPE_RESULT_SGX},
}

// teeNames returns the names of all hardware trust anchors with a policy OID.
func teeNames() []string {
	names := make([]string, 0, len(teeArcs))
	for _, t := range teeArcs {
		names = append(names, t.name)
	}
	return names
}

// Tree derives the policy OIDs from a base arc.
type Tree struct {
	arc string
}

// New returns the policy tree below the given base arc, e.g. 1.3.6.1.4.1.<PEN>.1.
func New(arc string) (*Tree, error) {
	if _, err := x509.ParseOID(arc); err != nil {
		return nil, fmt.Errorf("invalid certificate policy arc %q: %w", arc, err)
	}
	return &Tree{arc: arc}, nil
}

func (t *Tree) oid(sub ...int) x509.OID {
	var b strings.Builder
	b.WriteString(t.arc)
	for _, n := range sub {
		fmt.Fprintf(&b, ".%d", n)
	}
	// The arc is validated in New and the sub-arcs are non-negative
	oid, err := x509.ParseOID(b.String())
	if err != nil {
		panic(fmt.Sprintf("invalid certificate policy OID %v: %v", b.String(), err))
	}
	return oid
}

// Level returns the policy OID of an attestation level. LevelNone has no OID.
func (t *Tree) Level(l ar.AttestLevel) (x509.OID, error) {
	switch l {
	case ar.LevelSoftware:
		return t.oid(1, 1), nil
	case ar.LevelHardware:
		return t.oid(1, 2), nil
	}
	return x509.OID{}, fmt.Errorf("attestation level %v has no policy OID", l)
}

// Tee returns the policy OID of a hardware trust anchor.
func (t *Tree) Tee(name string) (x509.OID, error) {
	for _, tee := range teeArcs {
		if tee.name == name {
			return t.oid(2, tee.arc), nil
		}
	}
	return x509.OID{}, fmt.Errorf("unknown trust anchor %q, expected one of %v", name,
		strings.Join(teeNames(), ", "))
}

// FromResult returns the policy OIDs for a key enrolled with the given accepted attestation
// result: the attestation level the result reached and every verified hardware trust anchor. A
// nil result, i.e., an enrollment without attestation, yields no OIDs.
func (t *Tree) FromResult(result *ar.AttestationResult) []x509.OID {
	if result == nil {
		return nil
	}

	var oids []x509.OID
	if oid, err := t.Level(result.AttestLevel); err == nil {
		oids = append(oids, oid)
	}
	for _, tee := range teeArcs {
		if slices.ContainsFunc(result.Measurements, func(m ar.MeasurementResult) bool {
			return m.Type == tee.result
		}) {
			oids = append(oids, t.oid(2, tee.arc))
		}
	}
	return oids
}

// levelPolicies returns the policy OIDs of all attestation levels of at least minLevel. A
// certificate satisfies the minimum level if it carries any one of them.
func (t *Tree) levelPolicies(minLevel ar.AttestLevel) ([]x509.OID, error) {
	if minLevel < ar.LevelNone || minLevel > ar.LevelHardware {
		return nil, fmt.Errorf("unknown attestation level %v", minLevel)
	}
	var oids []x509.OID
	for l := max(minLevel, ar.LevelSoftware); l <= ar.LevelHardware; l++ {
		oid, _ := t.Level(l)
		oids = append(oids, oid)
	}
	return oids, nil
}

// Check checks that the certificate states an attestation level of at least minLevel through its
// policies. The caller must have validated the certificate chain. Only the policies of the leaf
// certificate are checked, as Go does not support enforcing policies through RFC 5280 policy
// processing.
func (t *Tree) Check(cert *x509.Certificate, minLevel ar.AttestLevel) error {
	oids, err := t.levelPolicies(minLevel)
	if err != nil {
		return err
	}
	if minLevel == ar.LevelNone {
		return nil
	}
	for _, p := range cert.Policies {
		if slices.ContainsFunc(oids, p.Equal) {
			return nil
		}
	}
	return fmt.Errorf("certificate %q does not state attestation level %v or higher",
		cert.Subject.CommonName, minLevel)
}

// VerifyConnection returns a tls.Config.VerifyConnection callback that requires an attestation
// level of at least minLevel from the peer certificate. The TLS stack must validate the peer
// certificate chain.
func (t *Tree) VerifyConnection(minLevel ar.AttestLevel) (func(tls.ConnectionState) error, error) {
	if _, err := t.levelPolicies(minLevel); err != nil {
		return nil, err
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 {
			return errors.New("peer certificate chain was not verified")
		}
		return t.Check(cs.VerifiedChains[0][0], minLevel)
	}, nil
}
