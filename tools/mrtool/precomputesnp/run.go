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

package precomputesnp

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type PrecomputeSnpConf struct {
	Kernel     string
	InitRfs    string
	CmdLine    string
	OvmfFile   string
	vcpuCounts []int
	vmmType    VmmType
	SnpDigests [][]byte
}

// alternativeGroup marks the generated reference values as mutually exclusive states of the SNP
// measurement register, of which exactly one must match
const alternativeGroup = "snp-measurement"

const (
	kernelFlag    = "kernel"
	initRfsFlag   = "initrd"
	cmdFlag       = "cmdline"
	ovmfFlag      = "ovmf"
	vcpuCountFlag = "vcpus"
	vmmTypeFlag   = "vmm-type"
	snpDigestFlag = "snp-digest"
)

type SnpHash = [sha512.Size384]byte

type VmmType = int

type VmmStruct struct {
	Value VmmType
	Label string
}

var (
	VmmTypeQemu = VmmStruct{Value: VmmType(1), Label: "qemu"}
	VmmTypeEc2  = VmmStruct{Value: VmmType(2), Label: "ec2"}
)

var (
	log = logrus.WithField("service", "mrtool")
)

var Command = &cli.Command{
	Name:  "snp",
	Usage: "precompute the values of the AMD SEV-SNP measurement register based on the OVMF and other optional files",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  ovmfFlag,
			Usage: "Filename of the OVMF.fd file",
		},
		&cli.StringFlag{
			Name:  kernelFlag,
			Usage: "Filename of the kernel image (if it should be included in the measurement)",
		},
		&cli.StringFlag{
			Name:  initRfsFlag,
			Usage: "Filename of the initramfs (if it should be included in the measurement)",
		},
		&cli.StringFlag{
			Name:  cmdFlag,
			Usage: "Filename of the kernel commandline (if it should be included in the measurement)",
		},
		&cli.UintSliceFlag{
			Name: vcpuCountFlag,
			Usage: "Number of vCPUs to use. Accepts a list (e.g. 1,2,4,8,16) to generate one " +
				"alternative reference value per vCPU count",
			Value: []uint{1},
		},
		&cli.StringFlag{
			Name:  vmmTypeFlag,
			Usage: fmt.Sprintf("VMM type to use [%s, %s]", VmmTypeQemu.Label, VmmTypeEc2.Label),
			Value: VmmTypeQemu.Label,
		},
		&cli.StringSliceFlag{
			Name: snpDigestFlag,
			Usage: "Already precomputed hexadecimal SNP launch digest to generate a reference " +
				"value for (alternative to specifying OVMF). Accepts a list to generate one " +
				"alternative reference value per digest",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := run(cmd)
		if err != nil {
			return fmt.Errorf("failed to precompute snp: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {
	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	snpConfig, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid snp config: %w", err)
	}

	log.Info("Precomputing AMD SEV-SNP measurement register...")

	type digest struct {
		hash        []byte
		description string
	}

	digests := make([]digest, 0)
	if len(snpConfig.SnpDigests) > 0 {
		for _, d := range snpConfig.SnpDigests {
			digests = append(digests, digest{hash: d, description: "SNP launch digest"})
		}
	} else {
		for _, vcpus := range snpConfig.vcpuCounts {
			hash, err := performSnpPrecomputation(snpConfig, vcpus)
			if err != nil {
				return fmt.Errorf("failed to perform snp precomputation for %v vCPUs: %w",
					vcpus, err)
			}
			digests = append(digests, digest{
				hash:        hash,
				description: fmt.Sprintf("SNP launch digest for %d vCPUs", vcpus),
			})
		}
	}

	// Several digests are mutually exclusive states of the single SNP measurement register, so
	// they must be declared as alternatives for the verifier to accept any one of them
	group := ""
	if len(digests) > 1 {
		group = alternativeGroup
	}

	refValues := make([]attestationreport.Component, 0, len(digests))
	for _, d := range digests {
		comp := attestationreport.Component{
			Type: attestationreport.CycloneDxType(attestationreport.TRUST_ANCHOR_SNP, 0),
			Name: "SNP Launch Digest",
			Hashes: []attestationreport.ReferenceHash{
				{
					Alg:     "SHA-384",
					Content: d.hash,
				},
			},
			Description:      d.description,
			AlternativeGroup: group,
		}
		comp.SetTrustAnchor(attestationreport.TRUST_ANCHOR_SNP)
		comp.SetIndex(0)
		refValues = append(refValues, comp)
	}

	// marshal eventlog
	data, err := json.MarshalIndent(refValues, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal reference values: %w", err)
	}

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	log.Info("Finished")

	return nil
}

func getConfig(cmd *cli.Command) (*PrecomputeSnpConf, error) {

	config := &PrecomputeSnpConf{}
	if cmd.IsSet(kernelFlag) {
		config.Kernel = cmd.String(kernelFlag)
	}
	if cmd.IsSet(initRfsFlag) {
		config.InitRfs = cmd.String(initRfsFlag)
	}
	if cmd.IsSet(cmdFlag) {
		config.CmdLine = cmd.String(cmdFlag)
	}
	if cmd.IsSet(ovmfFlag) {
		config.OvmfFile = cmd.String(ovmfFlag)
	}
	if cmd.IsSet(snpDigestFlag) {
		for _, s := range cmd.StringSlice(snpDigestFlag) {
			digest, err := hex.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("failed to decode provided SNP launch digest %q: %w", s, err)
			}
			config.SnpDigests = append(config.SnpDigests, digest)
		}
	}

	// [vcpuCountFlag] must be available, as its defaulted
	for _, v := range cmd.UintSlice(vcpuCountFlag) {
		if v == 0 {
			return nil, fmt.Errorf("number of vcpus must be greater than zero. See mrtool precompute snp --help")
		}
		config.vcpuCounts = append(config.vcpuCounts, int(v))
	}

	// validate the config
	if cmd.IsSet(ovmfFlag) && cmd.IsSet(snpDigestFlag) {
		return nil, fmt.Errorf("flags %q and %q cannot both be set", ovmfFlag, snpDigestFlag)
	}
	if len(config.OvmfFile) == 0 && len(config.SnpDigests) == 0 {
		return nil, fmt.Errorf("either OVMF must or precomputed SNP launch digest must be specified. See mrtool precompute snp --help")
	}
	if len(config.vcpuCounts) == 0 {
		return nil, fmt.Errorf("number of vcpus must be specified. See mrtool precompute snp --help")
	}

	// match the vmm-type ([vmmTypeFlag] must be set, as its defaulted)
	switch cmd.String(vmmTypeFlag) {
	case VmmTypeQemu.Label:
		config.vmmType = VmmTypeQemu.Value
	case VmmTypeEc2.Label:
		config.vmmType = VmmTypeEc2.Value
	default:
		return nil, fmt.Errorf("unsupported vmm-type [%s] encountered. See mrtool precompute snp --help", cmd.String(vmmTypeFlag))
	}

	// log the config for debugging purposes
	log.Debugf("SNP Config")
	if len(config.Kernel) > 0 {
		log.Debugf("\tKernel file       : %q", config.Kernel)
	}
	if len(config.InitRfs) > 0 {
		log.Debugf("\tInit ramfs file   : %q", config.InitRfs)
	}
	if len(config.CmdLine) > 0 {
		log.Debugf("\tKernel commandline: %q", config.CmdLine)
	}
	if len(config.OvmfFile) > 0 {
		log.Debugf("\tOVMF file         : %q", config.OvmfFile)
	}
	for _, d := range config.SnpDigests {
		log.Debugf("\tSNP Launch Digest : %x", d)
	}
	log.Debugf("\tvCPU counts       : %v", config.vcpuCounts)
	return config, nil
}
