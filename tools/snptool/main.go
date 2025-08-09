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
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
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
	CMD_GET_REPORT    = "get-report"
	CMD_GET_CERTCHAIN = "get-certchain"
	CMD_PARSE_REPORT  = "parse-report"
)

func run() error {

	cmd := flag.String("cmd", "", fmt.Sprintf("command to run: %v, %v, %v",
		CMD_GET_REPORT,
		CMD_GET_CERTCHAIN,
		CMD_PARSE_REPORT,
	))
	in := flag.String("in", "", "input file")
	flag.Parse()

	switch *cmd {

	case CMD_GET_REPORT:
		quote, err := getReport()
		if err != nil {
			return fmt.Errorf("failed to get SNP Quote: %w", err)
		}
		os.Stdout.Write(quote)

	case CMD_GET_CERTCHAIN:
		certChain, err := getCertChain()
		if err != nil {
			return fmt.Errorf("failed to get SNP cet chain: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_REPORT:
		err := parseReport(*in)
		if err != nil {
			return fmt.Errorf("failed to get SNP collateral: %w", err)
		}

	default:
		return fmt.Errorf("unknown cmd %q. See tdxquote -help", *cmd)

	}

	return nil
}

func getReport() ([]byte, error) {
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	data, err := snpdriver.GetMeasurement(nonce, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP Quote: %w", err)
	}

	return data, nil
}

func getCertChain() ([]byte, error) {

	return nil, fmt.Errorf("get certitifcate chain not implemented yet")
}

func parseReport(in string) error {

	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("failed to read quote: %w", err)
	}

	// Extract the SNP attestation report data structure
	report, err := verifier.DecodeSnpReport(data)
	if err != nil {
		return fmt.Errorf("failed to decode SNP report: %w", err)
	}

	log.Debugf("Version:           %v", report.Version)
	log.Debugf("GuestSvn:          %v", report.GuestSvn)
	log.Debugf("Policy:            0x%016x", report.Policy)
	log.Debugf("    single_socket: %v", (report.Policy&(1<<20)) != 0)
	log.Debugf("    debug:         %v", (report.Policy&(1<<19)) != 0)
	log.Debugf("    migrate_ma:    %v", (report.Policy&(1<<18)) != 0)
	log.Debugf("    smt:           %v", (report.Policy&(1<<16)) != 0)
	log.Debugf("    abi_major:     0x%02x (%d)", uint8(report.Policy>>8), uint8(report.Policy>>8))
	log.Debugf("    abi_minor:     0x%02x (%d)", uint8(report.Policy), uint8(report.Policy))
	log.Debugf("FamilyId:          %v", hex.EncodeToString(report.FamilyId[:]))
	log.Debugf("ImageId:           %v", hex.EncodeToString(report.ImageId[:]))
	log.Debugf("Vmpl:              %v", report.Vmpl)
	log.Debugf("SignatureAlgo:     0x%08x", report.SignatureAlgo)
	log.Debugf("SignatureAlgo:     0x%08x", report.SignatureAlgo)
	switch report.SignatureAlgo {
	case 1:
		log.Debugf("    description:   ECDSA P-384 with SHA-384")
	default:
		log.Debugf("    description:   Unknown")
	}
	log.Debugf("CurrentTcb:        0x%016x", report.CurrentTcb)
	log.Debugf("    bl:            %d", uint8(report.CurrentTcb))
	log.Debugf("    tee:           %d", uint8(report.CurrentTcb>>8))
	log.Debugf("    snp:           %d", uint8(report.CurrentTcb>>48))
	log.Debugf("    ucode:         %d", uint8(report.CurrentTcb>>56))
	log.Debugf("PlatformInfo:      0x%016x", report.PlatformInfo)
	log.Debugf("    tsme_en:       %v", (report.PlatformInfo&(1<<1)) != 0)
	log.Debugf("    smt_en:        %v", (report.PlatformInfo&(1<<0)) != 0)
	log.Debugf("KeySelection:      0x%08x", report.KeySelection)
	signingKey := (report.KeySelection >> 2) & 0x7
	switch signingKey {
	case 0:
		log.Debugf("    signing_key:   VCEK")
	case 1:
		log.Debugf("    signing_key:   VLEK")
	case 7:
		log.Debugf("    signing_key:   None")
	default:
		log.Debugf("    signing_key:   Undefined")
	}
	log.Debugf("    mask_chip_key: %v", (report.KeySelection&(1<<1)) != 0)
	log.Debugf("    author_key_en: %v", (report.KeySelection&(1<<0)) != 0)
	log.Debugf("ReportData:        %v", hex.EncodeToString(report.ReportData[:]))
	log.Debugf("Measurement:       %v", hex.EncodeToString(report.Measurement[:]))
	log.Debugf("HostData:          %v", hex.EncodeToString(report.HostData[:]))
	log.Debugf("IdKeyDigest:       %v", hex.EncodeToString(report.IdKeyDigest[:]))
	log.Debugf("AuthorKeyDigest:   %v", hex.EncodeToString(report.AuthorKeyDigest[:]))
	log.Debugf("ReportId:          %v", hex.EncodeToString(report.ReportId[:]))
	log.Debugf("ReportIdMa:        %v", hex.EncodeToString(report.ReportIdMa[:]))
	log.Debugf("ReportedTcb:       0x%016x", report.ReportedTcb)
	log.Debugf("ChipId:            %v", hex.EncodeToString(report.ChipId[:]))
	log.Debugf("CommittedTcb:      0x%016x", report.CommittedTcb)
	log.Debugf("CurrentBuild:      0x%02x (%d)", report.CurrentBuild, report.CurrentBuild)
	log.Debugf("CurrentMinor:      0x%02x (%d)", report.CurrentMinor, report.CurrentMinor)
	log.Debugf("CurrentMajor:      0x%02x (%d)", report.CurrentMajor, report.CurrentMajor)
	log.Debugf("CommittedBuild:    0x%02x (%d)", report.CommittedBuild, report.CommittedBuild)
	log.Debugf("CommittedMinor:    0x%02x (%d)", report.CommittedMinor, report.CommittedMinor)
	log.Debugf("CommittedMajor:    0x%02x (%d)", report.CommittedMajor, report.CommittedMajor)
	log.Debugf("LaunchTcb:         0x%016x", report.LaunchTcb)
	log.Debugf("SignatureR:        %v", hex.EncodeToString(report.SignatureR[:]))
	log.Debugf("SignatureS:        %v", hex.EncodeToString(report.SignatureS[:]))

	return nil
}
