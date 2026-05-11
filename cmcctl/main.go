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
)

func main() {
	cmd := &cli.Command{
		Name:  "cmcctl",
		Usage: "CLI client for the CMC daemon",
		Flags: flags,
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate attestation report",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					return c.api.generate(c)
				},
			},
			{
				Name:  "verify",
				Usage: "Verify attestation report",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					return c.api.verify(c)
				},
			},
			{
				Name:  "enroll-key",
				Usage: "Create and enroll a new TLS key",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					return c.api.enroll(c)
				},
			},
			{
				Name:  "dial",
				Usage: "Establish attested TLS client",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					if len(c.RootCas) == 0 {
						return fmt.Errorf("path to root CAs must be specified via config file or command line")
					}
					return dial(c)
				},
			},
			{
				Name:  "listen",
				Usage: "Establish attested TLS server",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					if len(c.RootCas) == 0 {
						return fmt.Errorf("path to root CAs must be specified via config file or command line")
					}
					return listen(c)
				},
			},
			{
				Name:  "request",
				Usage: "Perform an attested HTTPS request",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					if len(c.RootCas) == 0 {
						return fmt.Errorf("path to root CAs must be specified via config file or command line")
					}
					return request(c)
				},
			},
			{
				Name:  "serve",
				Usage: "Establish an attested HTTPS server",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					if len(c.RootCas) == 0 {
						return fmt.Errorf("path to root CAs must be specified via config file or command line")
					}
					return serve(c)
				},
			},
			{
				Name:  "token",
				Usage: "Request a bootstrap token for EST certificate requests",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					return createToken(c)
				},
			},
			{
				Name:  "provision",
				Usage: "Retrieve provisioning data for CVMs",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					if c.CaStorePath == "" {
						return fmt.Errorf("path to store CA must be specified via config file or command line")
					}
					if c.ProvisionToken == "" {
						return fmt.Errorf("provision token must be specified via config file or command line")
					}
					return retrieveProvisioningData(c)
				},
			},
			{
				Name:  "update-certs",
				Usage: "Triggers updating the CMC AK and IK certificates",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					return c.api.updateCerts(c)
				},
			},
			{
				Name:  "update-metadata",
				Usage: "Triggers updating the CMC metadata",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					return c.api.updateMetadata(c)
				},
			},
			{
				Name:  "proxy",
				Usage: "Forward data over attested TLS using HTTP",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c, err := getConfig(cmd)
					if err != nil {
						return err
					}
					if len(c.RootCas) == 0 {
						return fmt.Errorf("path to root CAs must be specified via config file or command line")
					}
					return forwardProxy(c)
				},
			},
		},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
