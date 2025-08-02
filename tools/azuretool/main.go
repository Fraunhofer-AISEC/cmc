// Copyright (c) 2025 Fraunhofer AISEC
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

	"github.com/Fraunhofer-AISEC/cmc/azuredriver"
	log "github.com/sirupsen/logrus"
)

func main() {

	log.SetLevel(log.TraceLevel)

	err := run()
	if err != nil {
		log.Errorf("%v", err)
	}
}

const (
	CMD_GET_AZURE_REPORT   = "get-azure-report"   // Fetches the azure report (header, hwreport, runtime-data)
	CMD_GET_AZURE_HWREPORT = "get-azure-hwreport" // Fetches the azure report payload, which is the SNP report or the TDX TDREPORT
	CMD_GET_HW_REPORT      = "get-hwreport"       // Fetches the hardware report (SNP report or TDX quote)
)

func run() error {

	cmd := flag.String("cmd", "", fmt.Sprintf("command to run: %v, %v, %v",
		CMD_GET_HW_REPORT,
		CMD_GET_AZURE_REPORT,
		CMD_GET_AZURE_HWREPORT,
	))
	flag.Parse()

	switch *cmd {

	case CMD_GET_HW_REPORT:
		quote, _, _, err := azuredriver.GetEvidence()
		if err != nil {
			return fmt.Errorf("failed to get hwreport: %w", err)
		}
		os.Stdout.Write(quote)

	case CMD_GET_AZURE_REPORT:
		tdreport, err := azuredriver.GetAzureReport()
		if err != nil {
			return fmt.Errorf("failed to get azure report: %w", err)
		}
		os.Stdout.Write(tdreport)

	case CMD_GET_AZURE_HWREPORT:
		tdreport, _, _, err := azuredriver.GetAzureHwReport()
		if err != nil {
			return fmt.Errorf("failed to get azure hwreport: %w", err)
		}
		os.Stdout.Write(tdreport)

	default:
		return fmt.Errorf("unknown cmd %q. See azuretool -help", *cmd)

	}

	return nil
}
