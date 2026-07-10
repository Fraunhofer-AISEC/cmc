package atlscaddy

import (
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// Common cmcd options. Do NOT give CmcOptions its own UnmarshalCaddyfile method, because
// a promoted unmarshaller would race the outer module parser
type CmcOptions struct {
	CmcApi     string `json:"cmc_api,omitempty"`
	CmcAddr    string `json:"cmc_addr,omitempty"`
	Serializer string `json:"serializer,omitempty"`
	PolicyFile string `json:"policy_file,omitempty"`
}

// buildCmcOptions converts the CmcOptions fields into a slice of
// attestedtls.ConnectionOption values for the CMC APIYes
func buildCmcOptions(o *CmcOptions) ([]atls.ConnectionOption[atls.CmcConfig], error) {
	opts := make([]atls.ConnectionOption[atls.CmcConfig], 0, 4)

	if o.CmcApi != "" {
		opts = append(opts, atls.WithCmcApi(o.CmcApi))
	}
	if o.CmcAddr != "" {
		opts = append(opts, atls.WithCmcAddr(o.CmcAddr))
	}
	if o.Serializer != "" {
		var s ar.Serializer
		var err error
		switch o.Serializer {
		case "json":
			s, err = ar.NewJsonSerializer()
		case "cbor":
			s, err = ar.NewCborSerializer()
		default:
			return nil, fmt.Errorf("invalid serializer: %s", o.Serializer)
		}
		if err != nil {
			return nil, fmt.Errorf("could not create %s serializer: %w", o.Serializer, err)
		}
		opts = append(opts, atls.WithSerializer(s))
	}
	if o.PolicyFile != "" {
		policy, err := os.ReadFile(o.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("could not open policy file: %w", err)
		}
		opts = append(opts, atls.WithCmcPolicies(policy))
	}
	return opts, nil
}

// parseCmcOption handles a single directive from within a module's UnmarshalCaddyfile block loop
func parseCmcOption(d *caddyfile.Dispenser, o *CmcOptions) (matched bool, err error) {
	switch d.Val() {
	case "cmc_api":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		o.CmcApi = d.Val()
	case "cmc_addr":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		o.CmcAddr = d.Val()
	case "serializer":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		o.Serializer = d.Val()
	case "policy_file":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		o.PolicyFile = d.Val()
	default:
		return false, nil
	}
	return true, nil
}
