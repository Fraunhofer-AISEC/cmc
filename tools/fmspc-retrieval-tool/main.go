package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

const (
	encryptedPpidFlag = "encrypted_ppid"
	pceidFlag         = "pceid"
	cpusvnFlag        = "cpusvn"
	pcesvnFlag        = "pcesvn"

	pckCertUrlTemplate = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid=%s&cpusvn=%s&pceid=%s&pcesvn=%s"
)

func main() {
	cmd := &cli.Command{
		Name:  "fmspc-retrieval-tool",
		Usage: "Retrieve an FMSPC value from Intel's PCK certificate service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     encryptedPpidFlag,
				Usage:    "Encrypted PPID string",
				Required: true,
			},
			&cli.StringFlag{
				Name:     pceidFlag,
				Usage:    "PCEID string",
				Required: true,
			},
			&cli.StringFlag{
				Name:     cpusvnFlag,
				Usage:    "CPUSVN string",
				Required: true,
			},
			&cli.StringFlag{
				Name:     pcesvnFlag,
				Usage:    "PCESVN string",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return run(cmd)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cli.Command) error {
	url := fmt.Sprintf(pckCertUrlTemplate,
		cmd.String(encryptedPpidFlag),
		cmd.String(cpusvnFlag),
		cmd.String(pceidFlag),
		cmd.String(pcesvnFlag),
	)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to retrieve PCK certificate: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	cert, err := internal.ParseCertsPem(body)
	if err != nil {
		return fmt.Errorf("failed to parse PEM certificate: %w", err)
	}

	sgxExtensions, err := verifier.ParseSGXExtensions(cert[0].Extensions[verifier.SGX_EXTENSION_INDEX].Value[4:])
	if err != nil {
		return fmt.Errorf("failed to parse SGX extensions: %w", err)
	}
	fmt.Print(hex.EncodeToString(sgxExtensions.Fmspc.Value))
	return nil
}
