package atlscaddy

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

var logAdapterSetup sync.Once

func init() {
	caddy.RegisterModule(ATlsModule{})
}

type ATlsModule struct {
	// Config
	CmcApi          string `json:"cmc_api,omitempty"`
	CmcAddr         string `json:"cmc_addr,omitempty"`
	AttestationMode string `json:"attestation_mode,omitempty"`
	Serializer      string `json:"serializer,omitempty"`
	PolicyFile      string `json:"policy_file,omitempty"`

	cmcConfig *atls.CmcConfig
	logger    *zap.Logger
}

func (ATlsModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.atls",
		New: func() caddy.Module { return new(ATlsModule) },
	}
}

func (m *ATlsModule) createConfig() error {
	configOpts := make([]atls.ConnectionOption[atls.CmcConfig], 0)

	if m.CmcApi != "" {
		m.logger.Debug("Configuring CMC API", zap.String("api", m.CmcApi))
		configOpts = append(configOpts, atls.WithCmcApi(m.CmcApi))
	}

	if m.CmcAddr != "" {
		m.logger.Debug("Configuring CMC address", zap.String("addr", m.CmcAddr))
		configOpts = append(configOpts, atls.WithCmcAddr(m.CmcAddr))
	}

	if m.AttestationMode != "" {
		m.logger.Debug("Configuring attestation mode", zap.String("attestation_mode", m.AttestationMode))
		var attest atls.AttestSelect
		switch m.AttestationMode {
		case "mutual":
			attest = atls.Attest_Mutual
		case "client":
			attest = atls.Attest_Client
		case "server":
			attest = atls.Attest_Server
		case "none":
			attest = atls.Attest_None
		default:
			return fmt.Errorf("invalid attestation mode: %s", m.AttestationMode)
		}
		configOpts = append(configOpts, atls.WithAttest(attest))
	}

	if m.Serializer != "" {
		m.logger.Debug("Configuring API serializer", zap.String("serializer", m.Serializer))
		var serializer ar.Serializer
		var err error
		switch m.Serializer {
		case "json":
			serializer, err = ar.NewJsonSerializer()
			if err != nil {
				return fmt.Errorf("could not create a json serializer: %w", err)
			}
		case "cbor":
			serializer, err = ar.NewCborSerializer()
			if err != nil {
				return fmt.Errorf("could not create a cbor serializer: %w", err)
			}
		default:
			return fmt.Errorf("invalid serializer: %s", m.Serializer)
		}
		configOpts = append(configOpts, atls.WithSerializer(serializer))
	}

	if m.PolicyFile != "" {
		m.logger.Debug("Configuring policy file", zap.String("policy_file", m.PolicyFile))
		policy, err := os.ReadFile(m.PolicyFile)
		if err != nil {
			return fmt.Errorf("could not open policy file: %w", err)
		}
		configOpts = append(configOpts, atls.WithCmcPolicies(policy))
	}

	cmcConfig, err := atls.NewCmcConfig(configOpts...)
	if err != nil {
		return fmt.Errorf("invalid aTLS config: %w", err)
	}
	m.cmcConfig = cmcConfig
	return nil
}

func (m *ATlsModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if err := m.createConfig(); err != nil {
		return fmt.Errorf("error initiating aTLS config: %w", err)
	}

	// The CMC uses logrus, caddy uses zap, so we need to set up some redirection.
	// This must be placed in the provisioner function since this is where we first have access to the correct logger.
	logAdapterSetup.Do(func() {
		logrus.AddHook(&LogrusZapAdapter{m.logger})
		logrus.SetLevel(logrus.TraceLevel)
		logrus.SetOutput(io.Discard)
	})

	return nil
}

func (m *ATlsModule) WrapListener(l net.Listener) net.Listener {
	m.logger.Debug("Wrapping listener with aTLS", zap.String("address", l.Addr().String()))
	// TODO: We would actually need to verify that the listener is actually a TLS listener, but tls.listener is private.
	// 		 Reflection would work, but is not clean and would interfere with other legitimate listeners like https_redirect.
	return &atls.Listener{
		Listener:  l,
		CmcConfig: m.cmcConfig,
		// This is unused anyway, right?
		Config: nil,
	}
}

func (m *ATlsModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "cmc_api":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CmcApi = d.Val()
		case "cmc_addr":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CmcAddr = d.Val()
		case "attest":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AttestationMode = d.Val()
		case "serializer":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Serializer = d.Val()
		case "policy_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.PolicyFile = d.Val()
		}
	}

	return nil
}

var (
	_ caddy.Module          = (*ATlsModule)(nil)
	_ caddy.Provisioner     = (*ATlsModule)(nil)
	_ caddy.ListenerWrapper = (*ATlsModule)(nil)
	_ caddyfile.Unmarshaler = (*ATlsModule)(nil)
)
