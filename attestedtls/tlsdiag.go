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

package attestedtls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// tlsHandshakeError enriches a failed TLS handshake with diagnostic information.
func tlsHandshakeError(err error, config *tls.Config, peer, serverName string) error {

	details := tlsHandshakeDetails(err, config, serverName)
	if details == "" {
		return fmt.Errorf("failed to establish tls connection to %v: %w", peer, err)
	}
	return fmt.Errorf("failed to establish tls connection to %v: %w\n%v", peer, err, details)
}

func tlsHandshakeDetails(err error, config *tls.Config, serverName string) string {

	if config == nil {
		return ""
	}

	var lines []string

	// The TLS stack reports the certificates it could not verify through this error type.
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) && len(verifyErr.UnverifiedCertificates) > 0 {

		chain := verifyErr.UnverifiedCertificates

		lines = append(lines, fmt.Sprintf("peer presented %v certificate(s):", len(chain)))
		for i, cert := range chain {
			lines = append(lines, fmt.Sprintf("  [%v] %v", i, certDetails(cert)))
		}
		for _, hint := range certChainHints(chain, config, serverName) {
			lines = append(lines, "hint: "+hint)
		}

		// The full chain allows inspecting or re-importing the certificates, but is far too
		// verbose for an error message
		log.Tracef("Unverified peer certificate chain:\n%v", certChainPem(chain))

	} else if len(config.Certificates) > 0 {
		// Without a peer chain, the own certificates are the most likely cause: either the peer
		// rejected them (mTLS) or no certificate matching the requested server name was found
		lines = append(lines, fmt.Sprintf("presented %v own certificate chain(s):",
			len(config.Certificates)))
		for i, cert := range config.Certificates {
			if cert.Leaf == nil {
				lines = append(lines, fmt.Sprintf("  [%v] (leaf not parsed)", i))
				continue
			}
			lines = append(lines, fmt.Sprintf("  [%v] %v", i, certDetails(cert.Leaf)))
		}
	}

	return strings.Join(lines, "\n")
}

// certDetails returns a single-line summary of the properties relevant for debugging a failed
// chain validation
func certDetails(cert *x509.Certificate) string {

	details := fmt.Sprintf("subject %q, issuer %q", cert.Subject.String(), cert.Issuer.String())

	if len(cert.DNSNames) > 0 {
		details += fmt.Sprintf(", dns %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, 0, len(cert.IPAddresses))
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		details += fmt.Sprintf(", ips %v", ips)
	}
	details += fmt.Sprintf(", validity %v - %v, ca %v",
		cert.NotBefore.UTC().Format(time.RFC3339),
		cert.NotAfter.UTC().Format(time.RFC3339),
		cert.IsCA)

	if len(cert.SubjectKeyId) > 0 {
		details += fmt.Sprintf(", ski %v", hex.EncodeToString(cert.SubjectKeyId))
	}
	if len(cert.AuthorityKeyId) > 0 {
		details += fmt.Sprintf(", aki %v", hex.EncodeToString(cert.AuthorityKeyId))
	}

	return details
}

// certChainHints inspects the chain the peer presented for the common reasons why it could not
// be validated against the local trust store
func certChainHints(chain []*x509.Certificate, config *tls.Config, serverName string) []string {

	var hints []string

	leaf := chain[0]
	top := chain[len(chain)-1]

	switch {
	case isSelfSigned(leaf):
		hints = append(hints,
			"the peer presented a self-signed certificate. Add it to the trusted root CAs or "+
				"enable attestation-only trust to authorize the peer through its attestation report")

	case isSelfSigned(top):
		hints = append(hints, fmt.Sprintf(
			"the chain ends at the self-signed root CA %q, which is not in the local trust store",
			top.Subject.String()))

	case len(chain) == 1:
		hints = append(hints, fmt.Sprintf(
			"the peer sent only its leaf certificate, which was issued by %q. Either the peer does "+
				"not send the required intermediate CA certificate(s), or that CA is not trusted locally",
			top.Issuer.String()))

	default:
		hints = append(hints, fmt.Sprintf(
			"the chain ends at the intermediate CA %q, which is issued by %q. Either the peer does "+
				"not send the remaining intermediate CA certificate(s), or the issuing CA is not "+
				"trusted locally", top.Subject.String(), top.Issuer.String()))
	}

	// Distinguish a chain the peer sent incompletely from a trust store that does not contain
	// the issuing root CA: if the system trust store accepts the chain, only the configured
	// root CAs are the problem (e.g. the system certificates were not added to them)
	if config.RootCAs != nil {
		if system, err := x509.SystemCertPool(); err == nil {
			if verifyChain(chain, system, serverName) == nil {
				hints = append(hints,
					"the chain is valid against the system certificate pool, but not against the "+
						"configured root CAs. Check that system certificates are enabled "+
						"(allowSystemCerts)")
			}
		}
	}

	now := time.Now()
	for _, cert := range chain {
		if now.Before(cert.NotBefore) {
			hints = append(hints, fmt.Sprintf("certificate %q is not valid before %v",
				cert.Subject.String(), cert.NotBefore.UTC().Format(time.RFC3339)))
		}
		if now.After(cert.NotAfter) {
			hints = append(hints, fmt.Sprintf("certificate %q expired at %v",
				cert.Subject.String(), cert.NotAfter.UTC().Format(time.RFC3339)))
		}
	}

	if serverName != "" {
		if err := leaf.VerifyHostname(serverName); err != nil {
			hints = append(hints, fmt.Sprintf("the leaf certificate is not valid for %q: %v",
				serverName, err))
		}
	}

	return hints
}

// verifyChain validates the leaf of chain against roots, using the remaining certificates of
// the chain as intermediates
func verifyChain(chain []*x509.Certificate, roots *x509.CertPool, serverName string) error {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
		// The hint this is used for is about the trust anchor, not about key usages
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func certChainPem(chain []*x509.Certificate) string {
	buf := new(bytes.Buffer)
	for _, cert := range chain {
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Sprintf("(failed to encode chain: %v)", err)
		}
	}
	return buf.String()
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

// serverName returns the name the peer certificate is validated against: the explicitly
// configured SNI name, or otherwise the host part of the dialed address.
func serverName(config *tls.Config, peer string) string {
	if config.ServerName != "" {
		return config.ServerName
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return ""
	}
	return host
}
