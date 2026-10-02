package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	cli "github.com/urfave/cli/v3"
)

const (
	flagCertFile           = "cert"
	flagKeyFile            = "key"
	flagCACertFile         = "ca-cert"
	flagCAKeyFile          = "ca-key"
	flagMetadataCas        = "metadata-cas"
	flagPort               = "port"
	flagUpstream           = "upstream"
	flagUpstreamAccountKey = "upstream-account-key"
	flagUpstreamContact    = "upstream-contact"
	flagUpstreamCA         = "upstream-ca"
	serverTimeout          = 60 * time.Second
	upstreamConnectTimeout = 60 * time.Second
)

type config struct {
	port               uint16
	certPath           string
	keyPath            string
	caCertPath         string
	caKeyPath          string
	metadataCasPath    string
	upstream           string
	upstreamAccountKey string
	upstreamContact    []string
	upstreamCAPath     string
}

func createIssuer(cfg *config) (Issuer, error) {
	if cfg.upstream != "" {
		if cfg.caCertPath != "" || cfg.caKeyPath != "" {
			return nil, fmt.Errorf("flags [%v]/[%v] cannot be combined with [%v]", flagCACertFile, flagCAKeyFile, flagUpstream)
		}
		var rootCAs []byte
		if cfg.upstreamCAPath != "" {
			var err error
			rootCAs, err = os.ReadFile(cfg.upstreamCAPath)
			if err != nil {
				return nil, fmt.Errorf("reading upstream root CAs: %w", err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), upstreamConnectTimeout)
		defer cancel()
		issuer, err := NewUpstreamIssuer(ctx, UpstreamIssuerConfig{
			DirectoryURL:   cfg.upstream,
			AccountKeyPath: cfg.upstreamAccountKey,
			Contact:        cfg.upstreamContact,
			RootCAs:        rootCAs,
		})
		if err != nil {
			return nil, fmt.Errorf("connecting to upstream ACME server: %w", err)
		}
		log.Printf("Proxy mode: connected to upstream ACME server %s (account %s)", cfg.upstream, issuer.AccountURL)
		return issuer, nil
	}

	if (cfg.caCertPath == "") != (cfg.caKeyPath == "") {
		return nil, fmt.Errorf("flags [%v] and [%v] must be specified together", flagCACertFile, flagCAKeyFile)
	}
	if cfg.caCertPath != "" {
		issuer, err := NewLocalCAIssuerFromFiles(cfg.caCertPath, cfg.caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading CA: %w", err)
		}
		log.Printf("CA mode: loaded CA certificate from %s", cfg.caCertPath)
		return issuer, nil
	}
	issuer, err := NewEphemeralCAIssuer()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral CA: %w", err)
	}
	log.Printf("CA mode: generated ephemeral CA certificate")
	return issuer, nil
}

func loadMetadataCas(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading metadata CAs: %w", err)
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing metadata CA certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		data = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return certs, nil
}

func run(cfg *config) error {
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%v", cfg.port),
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
		IdleTimeout:  serverTimeout,
	}

	issuer, err := createIssuer(cfg)
	if err != nil {
		return err
	}
	state := NewAcmeState(issuer)

	if cfg.metadataCasPath != "" {
		cas, err := loadMetadataCas(cfg.metadataCasPath)
		if err != nil {
			return fmt.Errorf("loading metadata CAs: %w", err)
		}
		state.MetadataCas = cas
		log.Printf("Loaded %d metadata CA(s) — %s and %s challenges enabled", len(cas), ChallengeSoftwareAttest, ChallengeTpmCertify)
	}

	// check if a raw http server should be started
	if cfg.certPath == "" && cfg.keyPath == "" {
		httpServer.Handler = http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) { handleAcmeDispatch(state, req, resp, false) })
		if err := httpServer.ListenAndServe(); err != nil {
			return fmt.Errorf("error starting http server: %w", err)
		}
		return nil
	}

	// validate the argument files
	if info, err := os.Stat(cfg.certPath); err != nil || info.IsDir() {
		return fmt.Errorf("certificate path [%v] must be an existing file", cfg.certPath)
	}
	if info, err := os.Stat(cfg.keyPath); err != nil || info.IsDir() {
		return fmt.Errorf("key path [%v] must be an existing file", cfg.keyPath)
	}

	// start the https server
	httpServer.Handler = http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) { handleAcmeDispatch(state, req, resp, true) })
	if err := httpServer.ListenAndServeTLS(cfg.certPath, cfg.keyPath); err != nil {
		return fmt.Errorf("error starting https server: %w", err)
	}
	return nil
}

func main() {
	cmd := &cli.Command{
		Name: "acmeserver",
		Usage: "A small acme server for cmc attestation-based enrollment. Operates in CA mode (signs with a local CA) " +
			"or, if --upstream is provided, in proxy mode (relays orders to an upstream ACME server). " +
			"The server starts as HTTP, if no TLS certificate and key are provided.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  flagCertFile,
				Usage: "Path to TLS certificate for HTTPS",
			},
			&cli.StringFlag{
				Name:  flagKeyFile,
				Usage: "Path to TLS key for HTTPS",
			},
			&cli.StringFlag{
				Name:  flagCACertFile,
				Usage: "Path to CA certificate for signing issued certificates (ephemeral if omitted)",
			},
			&cli.StringFlag{
				Name:  flagCAKeyFile,
				Usage: "Path to CA private key for signing issued certificates (ephemeral if omitted)",
			},
			&cli.StringFlag{
				Name:  flagMetadataCas,
				Usage: "Path to PEM file with trusted metadata root CAs (necessary for " + ChallengeSoftwareAttest + " and " + ChallengeTpmCertify + " challenges)",
			},
			&cli.Uint16Flag{
				Name:        flagPort,
				Usage:       "Port the server listens on",
				HideDefault: true,
			},
			&cli.StringFlag{
				Name:  flagUpstream,
				Usage: "Directory URL of an upstream ACME server. Enables proxy mode: orders are relayed upstream instead of being signed locally",
			},
			&cli.StringFlag{
				Name:  flagUpstreamAccountKey,
				Usage: "Path to PEM-encoded EC private key for the upstream ACME account (created if missing; ephemeral if omitted)",
			},
			&cli.StringSliceFlag{
				Name:  flagUpstreamContact,
				Usage: "Contact URL (e.g. mailto:ops@example.com) registered with the upstream ACME account; may be repeated",
			},
			&cli.StringFlag{
				Name:  flagUpstreamCA,
				Usage: "Path to PEM file with root CAs trusted for the TLS connection to the upstream ACME server (system roots if omitted)",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			if !c.IsSet(flagPort) {
				return fmt.Errorf("flag [%v] must be specified", flagPort)
			}
			return run(&config{
				port:               c.Uint16(flagPort),
				certPath:           c.String(flagCertFile),
				keyPath:            c.String(flagKeyFile),
				caCertPath:         c.String(flagCACertFile),
				caKeyPath:          c.String(flagCAKeyFile),
				metadataCasPath:    c.String(flagMetadataCas),
				upstream:           c.String(flagUpstream),
				upstreamAccountKey: c.String(flagUpstreamAccountKey),
				upstreamContact:    c.StringSlice(flagUpstreamContact),
				upstreamCAPath:     c.String(flagUpstreamCA),
			})
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
