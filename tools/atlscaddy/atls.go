package atlscaddy

import (
	"fmt"
	"io"
	"net"
	"sync"

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
	CmcOptions

	AttestationMode string `json:"attestation_mode,omitempty"`

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
	opts, err := buildCmcOptions(&m.CmcOptions)
	if err != nil {
		return err
	}
	if m.CmcApi != "" {
		m.logger.Debug("Configuring CMC API", zap.String("api", m.CmcApi))
	}
	if m.CmcAddr != "" {
		m.logger.Debug("Configuring CMC address", zap.String("addr", m.CmcAddr))
	}
	if m.Serializer != "" {
		m.logger.Debug("Configuring API serializer", zap.String("serializer", m.Serializer))
	}
	if m.PolicyFile != "" {
		m.logger.Debug("Configuring policy file", zap.String("policy_file", m.PolicyFile))
	}

	if m.AttestationMode != "" {
		m.logger.Debug("Configuring attestation mode", zap.String("attestation_mode", m.AttestationMode))
		attest, err := atls.ParseAttestMode(m.AttestationMode)
		if err != nil {
			return err
		}
		opts = append(opts, atls.WithAttest(attest))
	}

	cmcConfig, err := atls.NewCmcConfig(opts...)
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
		matched, err := parseCmcOption(d, &m.CmcOptions)
		if err != nil {
			return err
		}
		if matched {
			continue
		}
		switch d.Val() {
		case "attest":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AttestationMode = d.Val()
		default:
			return d.Errf("unknown atls directive %q", d.Val())
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
