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
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	cmds = map[string]func(*config){
		"generate":        generateCmd,
		"verify":          verifyCmd,
		"measure":         measureCmd,
		"dial":            dialCmd,
		"listen":          listenCmd,
		"request":         requestCmd,
		"serve":           serveCmd,
		"token":           tokenCmd,
		"provision":       provisionCmd,
		"update-certs":    updateCertsCmd,
		"update-metadata": updateMetadataCmd,
	}
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "USAGE:\n\tcmcctl command [options]\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "COMMANDS:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  generate\tGenerate attestation report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  verify\tVerify attestation report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  dial\t\tEstablish attested TLS client\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  listen\tEstablish attested TLS server\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  request\tPerform an attested HTTPS request\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  serve\t\tEstablish an attested HTTPS server\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  token\t\tRequest a bootstrap token for EST certificate requests\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  measure\tRecord measurements\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  provision\tRetrieve provisioning data for CVMs\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  update-certs\tTriggers updating the CMC AK and IK certificates\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  update-metadata\tTriggers updating the CMC metadata\n")
		fmt.Fprintf(flag.CommandLine.Output(), "\nOPTIONS:\n")
		flag.PrintDefaults()
	}
}

func main() {

	cmd, name, err := getCommand()
	if err != nil {
		flag.Usage()
		log.Fatalf("%v", err)
		return
	}

	c, err := getConfig(os.Args[1])
	if err != nil {
		flag.Usage()
		log.Fatalf("Failed to get config: %v", err)
		return
	}

	log.Infof("Running command %v", name)

	cmd(c)
}

func getCommand() (func(*config), string, error) {

	if len(os.Args) < 2 {
		return nil, "", fmt.Errorf("expected command")
	}

	cmd := os.Args[1]

	cmdFunc, ok := cmds[strings.ToLower(cmd)]
	if !ok {
		return nil, "", fmt.Errorf("undefined command %v", cmd)
	}

	return cmdFunc, cmd, nil
}
