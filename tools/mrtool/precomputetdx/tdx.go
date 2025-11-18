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

package precomputetdx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var (
	log = logrus.WithField("service", "mrtool")
)

// UEFI Spec 2.10 Section 38.4.1:
// TPM PCR Index | CC Measurement Register Index | TDX-measurement register
// 0             |   0                           |   MRTD
// 1, 7          |   1                           |   RTMR[0]
// 2~6           |   2                           |   RTMR[1]
// 8~15          |   3                           |   RTMR[2]
const (
	MR_LEN       = 6
	INDEX_MRTD   = 0
	INDEX_RTMR0  = 1
	INDEX_RTMR1  = 2
	INDEX_RTMR2  = 3
	INDEX_RTMR3  = 4
	INDEX_MRSEAM = 5 // Additional reference value, not part of UEFI spec
)

type Config struct {
	*tcg.Conf
	TdxModule   string
	MrSeam      string
	Mrtd        string
	OvmfVersion string
	QemuVersion string
}

const (
	tdxmoduleFlag   = "tdxmodule"
	mrseamFlag      = "mrseam"
	mrtdFlag        = "mrtd"
	ovmfversionFlag = "ovmfversion"
	qemuversionFlag = "qemuversion"
)

var flags = []cli.Flag{
	&cli.StringFlag{Name: tdxmoduleFlag, Usage: "Path to the TDX-module binary"},
	&cli.StringFlag{Name: mrseamFlag, Usage: "The MRSEAM hash (alternative to --tdxmodule if hash is supplied externally)"},
	&cli.StringFlag{Name: mrtdFlag, Usage: "The MRTD hash (alternative to --ovmf if hash is supplied externally)"},
	&cli.StringFlag{Name: ovmfversionFlag, Usage: "The version of the OVMF image", Value: "edk2-stable202502"},
	&cli.StringFlag{Name: qemuversionFlag, Usage: "QEMU version", Value: "9.2.0"},
}

var Command = &cli.Command{
	Name:  "tdx",
	Usage: "precompute TDX measurement",
	Flags: append(tcg.Flags, flags...),
	Action: func(ctx context.Context, c *cli.Command) error {
		err := run(c)
		if err != nil {
			return fmt.Errorf("failed to precompute TDX MRs: %w", err)
		}
		return nil
	},
}

func getConfig(cmd *cli.Command) (*Config, error) {

	var err error
	c := &Config{}

	c.Conf, err = tcg.GetTcgConf(cmd)
	if err != nil {
		return nil, err
	}

	if cmd.IsSet(tdxmoduleFlag) {
		c.TdxModule = cmd.String(tdxmoduleFlag)
	}
	if cmd.IsSet(mrseamFlag) {
		c.MrSeam = cmd.String(mrseamFlag)
	}
	if cmd.IsSet(mrtdFlag) {
		c.Mrtd = cmd.String(mrtdFlag)
	}
	if cmd.IsSet(ovmfversionFlag) {
		c.OvmfVersion = cmd.String(ovmfversionFlag)
	} else {
		c.OvmfVersion = "edk2-stable202502"
	}
	if cmd.IsSet(qemuversionFlag) {
		c.QemuVersion = cmd.String(qemuversionFlag)
	} else {
		c.QemuVersion = "9.2.0"
	}

	c.print()

	return c, nil
}

func (c *Config) print() {

	log.Debugf("Precompute TDX configuration:")

	c.Conf.Print()

	if c.TdxModule != "" {
		log.Debugf("\tTDX Module: %q", c.TdxModule)
	}
	if c.MrSeam != "" {
		log.Debugf("\tMRSEAM: %q", c.MrSeam)
	}
	if c.Mrtd != "" {
		log.Debugf("\tMRTD: %q", c.Mrtd)
	}
	if c.OvmfVersion != "" {
		log.Debugf("\tOVMF Version: %q", c.OvmfVersion)
	}
	if c.QemuVersion != "" {
		log.Debugf("\tQEMU Version: %q", c.QemuVersion)
	}

}

func run(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	tpmConf, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid precompute tpm config: %w", err)
	}

	log.Debug("Precomputing Intel TDX measurement registers...")

	// Precompute all TPM measurements
	_, refvals, err := precompute(globConf.Mrs, tpmConf)
	if err != nil {
		return err
	}

	// Marshal eventlog
	data, err := json.MarshalIndent(refvals, "", "     ")
	if err != nil {
		return fmt.Errorf("failed to marshal reference values: %w", err)
	}

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	log.Debug("Finished")

	return nil
}

func precompute(mrNums []int, conf *Config) ([]*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	refvals := make([]*ar.ReferenceValue, 0)
	pcrs := make([]*ar.ReferenceValue, 0)

	for _, pcrNum := range mrNums {
		switch {
		case pcrNum == INDEX_RTMR1:
			pcr, rv, err := PrecomputeRtmr1(conf)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to precompute PCR%v: %w", pcrNum, err)
			}
			pcrs = append(pcrs, pcr)
			refvals = append(refvals, rv...)
		case pcrNum < MR_LEN:
			return nil, nil, fmt.Errorf("MR%v precomputation not yet implemented", pcrNum)
		default:
			return nil, nil, fmt.Errorf("Specification does not define MR%v", pcrNum)
		}
	}

	return pcrs, refvals, nil
}
