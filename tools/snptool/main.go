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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/exp/maps"

	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/drivers/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-sev-guest/client"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	logLevelFlag = "log-level"
	inFlag       = "in"
	outFlag      = "out"
	vmplFlag     = "vmpl"
)

var (
	logLevels = map[string]logrus.Level{
		"panic": logrus.PanicLevel,
		"fatal": logrus.FatalLevel,
		"error": logrus.ErrorLevel,
		"warn":  logrus.WarnLevel,
		"info":  logrus.InfoLevel,
		"debug": logrus.DebugLevel,
		"trace": logrus.TraceLevel,
	}

	log = logrus.WithField("service", "mrtool")
)

func main() {

	cmd := &cli.Command{
		Name:  "snptool",
		Usage: "A tool to fetch and parse AMD SEV-SNP attestation reports and certificate chains",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  logLevelFlag,
				Usage: fmt.Sprintf("Set log level. Possible: %v", strings.Join(maps.Keys(logLevels), ",")),
			},
			&cli.StringFlag{
				Name:  inFlag,
				Usage: "Name of the input file, e.g., an SNP report",
			},
			&cli.StringFlag{
				Name:  outFlag,
				Usage: "Name of the output file, e.g., an SNP report (default: stdout)",
			},
			&cli.IntFlag{
				Name:  vmplFlag,
				Usage: "VMPL to retrieve the attestation report for",
				Value: 0,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "get-report",
				Usage: "Retrieve and AMD SEV-SNP attestation report from the AMD PSP",
				Action: func(ctx context.Context, c *cli.Command) error {

					config, err := GetConfig(c)
					if err != nil {
						return fmt.Errorf("failed to get config: %w", err)
					}

					quote, err := getReport(config)
					if err != nil {
						return fmt.Errorf("failed to get SNP Quote: %w", err)
					}

					if config.Out == "" {
						os.Stdout.Write(quote)
					} else {
						err = os.WriteFile(config.Out, quote, 0644)
						if err != nil {
							return fmt.Errorf("failed to write report: %w", err)
						}
					}

					return nil
				},
			},
			{
				Name:  "parse-report",
				Usage: "Parse and AMD SEV-SNP attestation report",
				Action: func(ctx context.Context, c *cli.Command) error {

					config, err := GetConfig(c)
					if err != nil {
						return fmt.Errorf("failed to get config: %w", err)
					}

					err = parseReport(config.In)
					if err != nil {
						return fmt.Errorf("failed to get SNP collateral: %w", err)
					}
					return nil
				},
			},
			{
				Name:  "get-vcek",
				Usage: "Fetch the AMD SEV-SNP VCEK certificate from the AMD server",
				Action: func(ctx context.Context, c *cli.Command) error {

					config, err := GetConfig(c)
					if err != nil {
						return fmt.Errorf("failed to get config: %w", err)
					}

					data, err := getReport(config)
					if err != nil {
						return fmt.Errorf("failed to get SNP Quote: %w", err)
					}

					report, err := verifier.DecodeSnpReport(data)
					if err != nil {
						return fmt.Errorf("failed to decode SNP report: %w", err)
					}

					codeName := verifier.GetSnpCodeName(report.CpuFamilyId, report.CpuModelId)

					log.Debugf("Fetched code name %q for family ID 0x%x, model ID 0x%x", codeName,
						report.CpuFamilyId, report.CpuModelId)

					url := provision.SnpVcekUrl(codeName, report.ChipId[:], report.CurrentTcb)

					log.Debugf("Created VCEK URL %q", url)

					vcek, status, err := provision.DownloadVcek(url)
					if err != nil {
						return fmt.Errorf("failed to download VCEK. Status %v (%w)", status, err)
					}

					pem := internal.WriteCertPem(vcek)

					if config.Out == "" {
						os.Stdout.Write(pem)
					} else {
						err = os.WriteFile(config.Out, pem, 0644)
						if err != nil {
							return fmt.Errorf("failed to write report: %w", err)
						}
					}

					return nil
				},
			},
			{
				Name:  "get-vlek",
				Usage: "Fetch the AMD SEV-SNP VLEK certificate from an extended attestation report",
				Action: func(ctx context.Context, c *cli.Command) error {

					config, err := GetConfig(c)
					if err != nil {
						return fmt.Errorf("failed to get config: %w", err)
					}

					vlek, err := getVlek(config)
					if err != nil {
						return fmt.Errorf("failed to get SNP cet chain: %w", err)
					}

					data := internal.WriteCertPem(vlek)

					if config.Out == "" {
						os.Stdout.Write(data)
					} else {
						err = os.WriteFile(config.Out, data, 0644)
						if err != nil {
							return fmt.Errorf("failed to write report: %w", err)
						}
					}

					return nil
				},
			},
			{
				Name:  "get-codename",
				Usage: "Fetch the AMD SEV-SNP EPYC code name from via CPUID instructions",
				Action: func(ctx context.Context, c *cli.Command) error {

					config, err := GetConfig(c)
					if err != nil {
						return fmt.Errorf("failed to get config: %w", err)
					}

					codeName, err := getSnpCodeName()
					if err != nil {
						return fmt.Errorf("failed to get SNP code name: %w", err)
					}

					if config.Out == "" {
						os.Stdout.Write([]byte(codeName))
					} else {
						err = os.WriteFile(config.Out, []byte(codeName), 0644)
						if err != nil {
							return fmt.Errorf("failed to write report: %w", err)
						}
					}

					return nil
				},
			},
			{
				Name:  "parse-vcek",
				Usage: "Parse the AMD SEV-SNP VCEK certificate from the AMD server",
				Action: func(ctx context.Context, c *cli.Command) error {

					config, err := GetConfig(c)
					if err != nil {
						return fmt.Errorf("failed to get config: %w", err)
					}

					vcek, err := internal.ReadCert(config.In)
					if err != nil {
						return fmt.Errorf("failed to read certificate: %w", err)
					}

					err = parseVcek(vcek)
					if err != nil {
						return fmt.Errorf("failed to parse VCEK: %w", err)
					}

					return nil
				},
			},
		},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func getReport(c *Config) ([]byte, error) {
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	data, err := snpdriver.GetMeasurement(nonce, c.Vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP Quote: %w", err)
	}

	return data, nil
}

func getVlek(c *Config) (*x509.Certificate, error) {

	d, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/sev-guest")
	}
	defer d.Close()

	//lint:ignore SA1019 will be updated later
	_, certs, err := client.GetRawExtendedReportAtVmpl(d, [64]byte{0}, c.Vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP attestation report")
	}

	log.Debugf("Fetched extended SNP attestation report with certs length %v", len(certs))

	b := bytes.NewBuffer(certs)
	var vlek []byte
	for {
		log.Debug("Parsing cert table entry..")
		var entry snpdriver.SnpCertTableEntry
		err = binary.Read(b, binary.LittleEndian, &entry)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cert table entry: %w", err)
		}

		if entry == (snpdriver.SnpCertTableEntry{}) {
			log.Debugf("Reached last (zero) SNP cert table entry")
			break
		}

		log.Debugf("Found cert table entry with UUID %v", hex.EncodeToString(entry.Uuid[:]))

		if bytes.Equal(entry.Uuid[:], snpdriver.VlekUuid) {
			log.Debugf("Found VLEK offset %v length %v", entry.Offset, entry.Length)

			vlek = certs[entry.Offset : entry.Offset+entry.Length]
		}
	}

	if vlek == nil {
		return nil, errors.New("could not find VLEK in certificates")
	}

	cert, err := x509.ParseCertificate(vlek)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VLEK certificate")
	}

	return cert, nil
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

	codeName := verifier.GetSnpCodeName(report.CpuFamilyId, report.CpuModelId)

	fmt.Printf("Version:           %v\n", report.Version)
	fmt.Printf("GuestSvn:          %v\n", report.GuestSvn)
	fmt.Printf("Policy:            0x%016x\n", report.Policy)
	fmt.Printf("    single_socket: %v\n", (report.Policy&(1<<20)) != 0)
	fmt.Printf("    debug:         %v\n", (report.Policy&(1<<19)) != 0)
	fmt.Printf("    migrate_ma:    %v\n", (report.Policy&(1<<18)) != 0)
	fmt.Printf("    smt:           %v\n", (report.Policy&(1<<16)) != 0)
	fmt.Printf("    abi_major:     0x%02x (%d)\n", uint8(report.Policy>>8), uint8(report.Policy>>8))
	fmt.Printf("    abi_minor:     0x%02x (%d)\n", uint8(report.Policy), uint8(report.Policy))
	fmt.Printf("FamilyId:          %v\n", hex.EncodeToString(report.FamilyId[:]))
	fmt.Printf("ImageId:           %v\n", hex.EncodeToString(report.ImageId[:]))
	fmt.Printf("Vmpl:              %v\n", report.Vmpl)
	fmt.Printf("SignatureAlgo:     0x%08x\n", report.SignatureAlgo)
	fmt.Printf("SignatureAlgo:     0x%08x\n", report.SignatureAlgo)
	switch report.SignatureAlgo {
	case 1:
		fmt.Printf("    description:   ECDSA P-384 with SHA-384\n")
	default:
		fmt.Printf("    description:   Unknown\n")
	}
	fmt.Printf("PlatformInfo:      0x%016x\n", report.PlatformInfo)
	fmt.Printf("    tsme_en:       %v\n", (report.PlatformInfo&(1<<1)) != 0)
	fmt.Printf("    smt_en:        %v\n", (report.PlatformInfo&(1<<0)) != 0)
	fmt.Printf("KeySelection:      0x%08x\n", report.KeySelection)
	signingKey := (report.KeySelection >> 2) & 0x7
	switch signingKey {
	case 0:
		fmt.Printf("    signing_key:   VCEK\n")
	case 1:
		fmt.Printf("    signing_key:   VLEK\n")
	case 7:
		fmt.Printf("    signing_key:   None\n")
	default:
		fmt.Printf("    signing_key:   Undefined\n")
	}
	fmt.Printf("    mask_chip_key: %v\n", (report.KeySelection&(1<<1)) != 0)
	fmt.Printf("    author_key_en: %v\n", (report.KeySelection&(1<<0)) != 0)
	fmt.Printf("ReportData:        %v\n", hex.EncodeToString(report.ReportData[:]))
	fmt.Printf("Measurement:       %v\n", hex.EncodeToString(report.Measurement[:]))
	fmt.Printf("HostData:          %v\n", hex.EncodeToString(report.HostData[:]))
	fmt.Printf("IdKeyDigest:       %v\n", hex.EncodeToString(report.IdKeyDigest[:]))
	fmt.Printf("AuthorKeyDigest:   %v\n", hex.EncodeToString(report.AuthorKeyDigest[:]))
	fmt.Printf("ReportId:          %v\n", hex.EncodeToString(report.ReportId[:]))
	fmt.Printf("ReportIdMa:        %v\n", hex.EncodeToString(report.ReportIdMa[:]))
	fmt.Printf("CPU Info: (Only valid for report version >= 3)\n")
	fmt.Printf("    family         %x\n", report.CpuFamilyId)
	fmt.Printf("    model          %x\n", report.CpuModelId)
	fmt.Printf("    stepping       %x\n", report.CpuStepping)
	fmt.Printf("    name           %s\n", codeName)
	fmt.Printf("ChipId:            %v\n", hex.EncodeToString(report.ChipId[:]))
	parseTcbDetails(codeName, "CurrentTcb:", report.CurrentTcb)
	parseTcbDetails(codeName, "ReportedTcb:", report.CurrentTcb)
	parseTcbDetails(codeName, "CommittedTcb:", report.CurrentTcb)
	parseTcbDetails(codeName, "LaunchTcb:", report.CurrentTcb)
	fmt.Printf("CurrentMajor:      0x%02x (%d)\n", report.CurrentMajor, report.CurrentMajor)
	fmt.Printf("CurrentMinor:      0x%02x (%d)\n", report.CurrentMinor, report.CurrentMinor)
	fmt.Printf("CurrentBuild:      0x%02x (%d)\n", report.CurrentBuild, report.CurrentBuild)
	fmt.Printf("CommittedMajor:    0x%02x (%d)\n", report.CommittedMajor, report.CommittedMajor)
	fmt.Printf("CommittedMinor:    0x%02x (%d)\n", report.CommittedMinor, report.CommittedMinor)
	fmt.Printf("CommittedBuild:    0x%02x (%d)\n", report.CommittedBuild, report.CommittedBuild)
	fmt.Printf("Launch MIT Vector: 0x%016x\n", report.LaunchMitVector)
	fmt.Printf("Curr MIT Vector:   0x%016x\n", report.CurrMitVector)
	fmt.Printf("SignatureR:        %v\n", hex.EncodeToString(report.SignatureR[:]))
	fmt.Printf("SignatureS:        %v\n", hex.EncodeToString(report.SignatureS[:]))

	return nil
}

func parseTcbDetails(codeName, tcbName string, tcb uint64) {

	fmt.Printf("%-19s 0x%016x\n", tcbName, tcb)

	if codeName == "Milan" || codeName == "Genoa" {
		fmt.Printf("    bl:            %d\n", uint8(tcb))
		fmt.Printf("    tee:           %d\n", uint8(tcb>>8))
		fmt.Printf("    snp:           %d\n", uint8(tcb>>48))
		fmt.Printf("    ucode:         %d\n", uint8(tcb>>56))
	} else { // Turin
		fmt.Printf("    fmc:           %d\n", uint8(tcb))
		fmt.Printf("    bl:            %d\n", uint8(tcb>>8))
		fmt.Printf("    tee:           %d\n", uint8(tcb>>16))
		fmt.Printf("    snp:           %d\n", uint8(tcb>>24))
		fmt.Printf("    ucode:         %d\n", uint8(tcb>>56))
	}
}

func getSnpCodeName() (string, error) {

	eax, _, _, _ := cpuid(1)

	basicFamily := (eax >> 8) & 0xF
	baseModel := uint8((eax >> 4) & 0xF)
	extendedModel := uint8((eax >> 16) & 0xF)
	extendedFamily := (eax >> 20) & 0xFF
	combinedFamily := uint8(basicFamily + extendedFamily)
	combinedModel := uint8((extendedModel << 4) | baseModel)

	return verifier.GetSnpCodeName(combinedFamily, combinedModel), nil
}

func parseVcek(c *x509.Certificate) error {

	fmt.Printf("VCEK Certificate:\n")
	fmt.Printf("\tSubject: CN=%v, C=%v, O=%v\n", c.Subject.CommonName, c.Subject.Country, c.Subject.Organization)
	fmt.Printf("\tIssuer: CN=%v, C=%v, O=%v\n", c.Issuer.CommonName, c.Issuer.Country, c.Issuer.Organization)

	return nil
}
