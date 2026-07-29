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
	flagCertFile    = "cert"
	flagKeyFile     = "key"
	flagCACertFile  = "ca-cert"
	flagCAKeyFile   = "ca-key"
	flagMetadataCas = "metadata-cas"
	flagPort        = "port"
	serverTimeout   = 60 * time.Second
)

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

func run(port uint16, certPath, keyPath, caCertPath, caKeyPath, metadataCasPath string) error {
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%v", port),
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
		IdleTimeout:  serverTimeout,
	}
	state := NewAcmeState()

	if caCertPath != "" && caKeyPath != "" {
		if err := state.LoadCA(caCertPath, caKeyPath); err != nil {
			return fmt.Errorf("loading CA: %w", err)
		}
		log.Printf("Loaded CA certificate from %s", caCertPath)
	} else {
		if err := state.GenerateEphemeralCA(); err != nil {
			return fmt.Errorf("generating ephemeral CA: %w", err)
		}
		log.Printf("Generated ephemeral CA certificate")
	}

	if metadataCasPath != "" {
		cas, err := loadMetadataCas(metadataCasPath)
		if err != nil {
			return fmt.Errorf("loading metadata CAs: %w", err)
		}
		state.MetadataCas = cas
		log.Printf("Loaded %d metadata CA(s) — software-attest-01 challenges enabled", len(cas))
	}

	// check if a raw http server should be started
	if certPath == "" && keyPath == "" {
		httpServer.Handler = http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) { handleAcmeDispatch(state, req, resp, false) })
		if err := httpServer.ListenAndServe(); err != nil {
			return fmt.Errorf("error starting http server: %w", err)
		}
		return nil
	}

	// validate the argument files
	if info, err := os.Stat(certPath); err != nil || info.IsDir() {
		return fmt.Errorf("certificate path [%v] must be an existing file", certPath)
	}
	if info, err := os.Stat(keyPath); err != nil || info.IsDir() {
		return fmt.Errorf("key path [%v] must be an existing file", keyPath)
	}

	// start the https server
	httpServer.Handler = http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) { handleAcmeDispatch(state, req, resp, true) })
	if err := httpServer.ListenAndServeTLS(certPath, keyPath); err != nil {
		return fmt.Errorf("error starting https server: %w", err)
	}
	return nil
}

func main() {
	cmd := &cli.Command{
		Name:  "acmeserver",
		Usage: "A small test acme web server. If no certificate and key is provided, an http server is started.",
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
				Usage: "Path to PEM file with trusted metadata root CAs (enables software-attest-01 challenges)",
			},
			&cli.Uint16Flag{
				Name:        flagPort,
				Usage:       "Port the server listens on",
				HideDefault: true,
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			if !c.IsSet(flagPort) {
				return fmt.Errorf("Flag [%v] must be specified", flagPort)
			}
			return run(c.Uint16(flagPort), c.String(flagCertFile), c.String(flagKeyFile), c.String(flagCACertFile), c.String(flagCAKeyFile), c.String(flagMetadataCas))
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
