package atlscaddy

import (
	"crypto/x509"
	"errors"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/certpolicy"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(CertLevelVerifier{})
}

// CertLevelVerifier is a client certificate verifier with module ID
// `tls.client_auth.verifier.cert_level`. It requires the client certificate to state a minimum
// attestation level through its certificate policies (passport model), see package certpolicy.
type CertLevelVerifier struct {
	// Level is the minimum attestation level: "none", "software" or "hardware"
	Level string `json:"level,omitempty"`

	// Arc is the base OID of the certificate policies. Defaults to certpolicy.DefaultArc
	Arc string `json:"arc,omitempty"`

	level ar.AttestLevel
	tree  *certpolicy.Tree
}

func (CertLevelVerifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.cert_level",
		New: func() caddy.Module { return new(CertLevelVerifier) },
	}
}

func (v *CertLevelVerifier) Provision(_ caddy.Context) error {
	var err error
	v.level, err = ar.ParseAttestLevel(v.Level)
	if err != nil {
		return err
	}
	arc := v.Arc
	if arc == "" {
		arc = certpolicy.DefaultArc
	}
	v.tree, err = certpolicy.New(arc)
	return err
}

func (v *CertLevelVerifier) VerifyClientCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return errors.New("client certificate chain was not verified")
	}
	return v.tree.Check(verifiedChains[0][0], v.level)
}

func (v *CertLevelVerifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "level":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v.Level = d.Val()
		case "arc":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v.Arc = d.Val()
		default:
			return d.Errf("unknown cert_level directive %q", d.Val())
		}
	}

	return nil
}

var (
	_ caddy.Module                       = (*CertLevelVerifier)(nil)
	_ caddy.Provisioner                  = (*CertLevelVerifier)(nil)
	_ caddytls.ClientCertificateVerifier = (*CertLevelVerifier)(nil)
	_ caddyfile.Unmarshaler              = (*CertLevelVerifier)(nil)
)
