// Copyright (c) 2021 - 2025 Fraunhofer AISEC
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

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
)

// binaryName selects the config file and data folder of the binary
const binaryName = "cmcctl"

func main() {
	cmd := &cli.Command{
		Name:    binaryName,
		Usage:   "CLI client for the CMC daemon",
		Version: collectVersion(),
		Flags:   globalFlags(libapiSelected(os.Args)),
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate attestation report",
				Flags: flags(withFiles),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return c.api.generate(c)
				},
			},
			{
				Name:  "verify",
				Usage: "Verify attestation report",
				Flags: flags(withFiles, withPublish),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return c.api.verify(c)
				},
			},
			{
				Name:  "enroll-key",
				Usage: "Create and enroll a new TLS key",
				Flags: flags(withIdentity),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return c.api.enroll(c)
				},
			},
			{
				Name:  "dial",
				Usage: "Establish attested TLS client",
				Flags: flags(withAtls, withIdentity, withFiles, withPublish, withRequest),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return dial(c)
				},
			},
			{
				Name:  "listen",
				Usage: "Establish attested TLS server",
				Flags: flags(withAtls, withIdentity, withFiles, withPublish),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return listen(c)
				},
			},
			{
				Name:  "request",
				Usage: "Perform an attested HTTPS request",
				Flags: flags(withAtls, withIdentity, withFiles, withPublish, withRequest),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return request(c)
				},
			},
			{
				Name:  "serve",
				Usage: "Establish an attested HTTPS server",
				Flags: flags(withAtls, withIdentity, withFiles, withPublish),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return serve(c)
				},
			},
			{
				Name:  "token",
				Usage: "Request a bootstrap token for EST certificate requests",
				Flags: flags(withToken, withFiles),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					return createToken(c)
				},
			},
			{
				Name:  "provision",
				Usage: "Retrieve provisioning data for CVMs",
				Flags: flags(withFiles),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					return retrieveProvisioningData(c)
				},
			},
			{
				Name:  "update-certs",
				Usage: "Triggers updating the CMC AK and IK certificates",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return c.api.updateCerts(c)
				},
			},
			{
				Name:  "update-metadata",
				Usage: "Triggers updating the CMC metadata",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return c.api.updateMetadata(c)
				},
			},
			{
				Name:  "proxy",
				Usage: "Forward data over attested TLS using HTTP",
				Flags: flags(withAtls, withIdentity, withFiles, withPublish),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := loadConfig(cmd)
					if err != nil {
						return err
					}
					if err := c.initCmc(); err != nil {
						return err
					}
					return forwardProxy(c)
				},
			},
			{
				Name:  "kubeprov",
				Usage: "Kubernetes node provisioning via attested TLS",
				Commands: []*cli.Command{
					{
						Name:  "serve",
						Usage: "Distribute kubeadm join tokens to attested workers",
						Flags: flags(withAtls, withIdentity, withFiles, withKubeprov),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							c, err := loadConfig(cmd)
							if err != nil {
								return err
							}
							if len(c.Trust.RootCas) == 0 {
								return fmt.Errorf("path to root CAs must be specified via config file or command line")
							}
							if err := c.initCmc(); err != nil {
								return err
							}
							return kubeprovServe(c)
						},
					},
					{
						Name:  "join",
						Usage: "Join this node to a Kubernetes cluster via attested provisioning",
						Flags: flags(withAtls, withIdentity, withFiles, withKubeprov),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							c, err := loadConfig(cmd)
							if err != nil {
								return err
							}
							if len(c.Trust.RootCas) == 0 {
								return fmt.Errorf("path to root CAs must be specified via config file or command line")
							}
							if err := c.initCmc(); err != nil {
								return err
							}
							return kubeprovJoin(c)
						},
					},
				},
			},
			config.Command[Config](binaryName, func() []cli.Flag { return flags(allSections...) }),
		},
	}

	// Errors are printed directly rather than logged, so that the multi-line
	// report of a bad configuration stays readable
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func collectVersion() string {
	return fmt.Sprintf("%v, cmcd api version %v, atls protocol version %v",
		internal.GetVersionInfo().String(),
		api.GetVersion(),
		attestedtls.GetAtlsProtocolVersion())
}
