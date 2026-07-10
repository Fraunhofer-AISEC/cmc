package atlscaddy

import (
	"crypto/tls"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/api"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CmcCertLoader{})
	httpcaddyfile.RegisterDirective("cmc_cert", parseCmcCertDirective)
}

// CmcCertLoader is a Caddy CertificateLoader with module ID
// `tls.certificates.cmc`. It fetches TLS certificates with
// hardware-backed signing keys from the cmcd.
//
// Slice type to match the shape of Caddy's built-in FileLoader,
// which is required for integration with Caddy's
// Caddyfile-to-JSON adapter.
type CmcCertLoader []CmcCertConfig

// CmcCertConfig is a single hardware-backed certificate to load.
type CmcCertConfig struct {
	CmcOptions

	// KeyId is the CMC key UUID to reuse. Can be left empty on first run
	KeyId string `json:"key_id,omitempty"`

	// KeyIdFile is the path to persist the CMC-assigned key ID
	KeyIdFile string `json:"key_id_file,omitempty"`

	// KeyType selects the CMC key driver: "tpm", "snp", or "sw"
	KeyType string `json:"key_type,omitempty"`

	// KeyAlg selects the key algorithm: "EC256", "EC384", "EC521",
	// "RSA2048", or "RSA4096".
	KeyAlg string `json:"key_alg,omitempty"`

	// CommonName is the CN placed on the freshly created certificate
	CommonName string `json:"common_name,omitempty"`

	// DNSNames are the DNS SANs placed on the freshly created certificate.
	// Must include every hostname that a client's SNI may present.
	DNSNames []string `json:"dns_names,omitempty"`

	// IPAddresses are the IP SANs placed on the freshly created certificate
	IPAddresses []string `json:"ip_addresses,omitempty"`

	// Tags are attached to the loaded certificate for use with the
	// cert_selection policy in a site block
	Tags []string `json:"tags,omitempty"`

	cert tls.Certificate // resolved in Provision
}

func (CmcCertLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.cmc",
		New: func() caddy.Module { return new(CmcCertLoader) },
	}
}

func (cl CmcCertLoader) Provision(ctx caddy.Context) error {
	logger := ctx.Logger()
	for i := range cl {
		if err := cl[i].fetch(logger); err != nil {
			return fmt.Errorf("cmc cert loader entry %d: %w", i, err)
		}
	}
	return nil
}

func (e *CmcCertConfig) fetch(logger *zap.Logger) error {
	opts, err := buildCmcOptions(&e.CmcOptions)
	if err != nil {
		return err
	}
	opts = append(opts, atls.WithKeyConfig(api.TLSKeyConfig{
		Type:        e.KeyType,
		Alg:         e.KeyAlg,
		Cn:          e.CommonName,
		DNSNames:    e.DNSNames,
		IPAddresses: e.IPAddresses,
	}))

	logger.Debug("Fetching CMC certificate",
		zap.String("cmc_addr", e.CmcAddr),
		zap.String("cmc_api", e.CmcApi),
		zap.String("key_id_file", e.KeyIdFile),
		zap.String("common_name", e.CommonName),
		zap.Strings("dns_names", e.DNSNames),
		zap.Strings("ip_addresses", e.IPAddresses),
	)

	keyId := e.KeyId
	cert, err := atls.GetOrCreateCert(&keyId, e.KeyIdFile, opts...)
	if err != nil {
		return fmt.Errorf("fetch certificate: %w", err)
	}
	e.KeyId = keyId
	e.cert = cert

	if cert.Leaf != nil {
		logger.Info("Loaded CMC-issued certificate",
			zap.String("key_id", keyId),
			zap.String("subject", cert.Leaf.Subject.String()),
			zap.Strings("dns_sans", cert.Leaf.DNSNames),
			zap.Time("not_after", cert.Leaf.NotAfter),
		)
	}
	return nil
}

func (cl CmcCertLoader) LoadCertificates() ([]caddytls.Certificate, error) {
	out := make([]caddytls.Certificate, len(cl))
	for i, e := range cl {
		out[i] = caddytls.Certificate{
			Certificate: e.cert,
			Tags:        e.Tags,
		}
	}
	return out, nil
}

// UnmarshalCaddyfile parses one entry from a cmc_cert block and
// appends it to the loader. The directive name is consumed by the caller.
func (cl *CmcCertLoader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var e CmcCertConfig
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		matched, err := parseCmcOption(d, &e.CmcOptions)
		if err != nil {
			return err
		}
		if matched {
			continue
		}
		switch d.Val() {
		case "key_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.KeyId = d.Val()
		case "key_id_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.KeyIdFile = d.Val()
		case "key_type":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.KeyType = d.Val()
		case "key_alg":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.KeyAlg = d.Val()
		case "common_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.CommonName = d.Val()
		case "dns_names":
			e.DNSNames = append(e.DNSNames, d.RemainingArgs()...)
		case "ip_addresses":
			e.IPAddresses = append(e.IPAddresses, d.RemainingArgs()...)
		case "tags":
			e.Tags = append(e.Tags, d.RemainingArgs()...)
		default:
			return d.Errf("unknown cmc_cert directive %q", d.Val())
		}
	}
	*cl = append(*cl, e)
	return nil
}

// parseCmcCertDirective is the Caddyfile directive that wires
// a CmcCertLoader into the tls app. The loader is a slice-typed
// caddytls.CertificateLoader, so the Caddy tlsapp.go builder merges
// entries into a single `apps.tls.certificates.cmc` array.
//
// The effect is global: all loaded certs go into the shared
// cert cache. The site block just provides a home for the directive,
// matching the same convention Caddy uses for its built-in
// `tls cert.pem key.pem` file loader.
func parseCmcCertDirective(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	h.Next() // consume directive name
	var loader CmcCertLoader
	if err := loader.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return []httpcaddyfile.ConfigValue{{
		Class: "tls.cert_loader",
		Value: loader,
	}}, nil
}

var (
	_ caddy.Module               = (*CmcCertLoader)(nil)
	_ caddy.Provisioner          = (*CmcCertLoader)(nil)
	_ caddytls.CertificateLoader = (*CmcCertLoader)(nil)
	_ caddyfile.Unmarshaler      = (*CmcCertLoader)(nil)
)
