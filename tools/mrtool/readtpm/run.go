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

package readtpm

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
	"github.com/google/go-attestation/attest"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type ParsePcrsConf struct {
	PrintAggregate   bool
	HashAlg          crypto.Hash
	AggregateHashAlg crypto.Hash
}

const (
	printAggregateFlag = "print-aggregate"
	hashAlgFlag        = "hash-alg"
	aggregateAlgFlag   = "aggregate-hash-alg"
)

var (
	log = logrus.WithField("service", "mrtool")
)

var Command = &cli.Command{
	Name:  "tpm",
	Usage: "reads the TPM PCR values directly from the TPM",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  printAggregateFlag,
			Usage: "Print the aggregated PCR value over the selected PCRs",
		},
		&cli.StringFlag{
			Name: hashAlgFlag,
			Usage: "Hash algorithm of the TPM PCR bank to read. " +
				"Possible: SHA-1, SHA-256, SHA-384",
			Value: crypto.SHA256.String(),
		},
		&cli.StringFlag{
			Name: aggregateAlgFlag,
			Usage: "Hash algorithm the TPM uses to calculate the aggregated PCR value contained " +
				"in a quote. This is the hash algorithm of the signature scheme of the " +
				"attestation key and therefore independent of the PCR bank. " +
				"Possible: SHA-1, SHA-256, SHA-384",
			Value: crypto.SHA256.String(),
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := run(cmd)
		if err != nil {
			return fmt.Errorf("failed to read tpm pcrs: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	pcrConf, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid tdx config: %w", err)
	}

	err = checkConfig(globConf, pcrConf)
	if err != nil {
		return fmt.Errorf("failed to check parse pcrs config: %w", err)
	}

	log.Infof("Reading %v TPM PCRs", pcrConf.HashAlg.String())

	attestAlg, err := internal.CryptoToAttestHash(pcrConf.HashAlg)
	if err != nil {
		return fmt.Errorf("failed to convert hash algorithm: %w", err)
	}

	// Read PCRs from TPM and write to stdout
	tpm, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	pcrs, err := tpm.PCRs(attestAlg)
	if err != nil {
		return fmt.Errorf("failed to get TPM PCRs: %w", err)
	}

	refvals := make([]*ar.Component, 0)
	for _, pcr := range pcrs {
		if contains(globConf.Mrs, pcr.Index) {
			r := &ar.Component{
				Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TPM, pcr.Index),
				Name: ar.TYPE_PCR_SUMMARY,
				Hashes: []ar.ReferenceHash{
					{
						Alg:     pcrConf.HashAlg.String(),
						Content: pcr.Digest[:],
					},
				},
			}
			r.SetTrustAnchor(ar.TRUST_ANCHOR_TPM)
			r.SetIndex(pcr.Index)
			refvals = append(refvals, r)
		}
	}

	if globConf.PrintEventLog {
		data, err := json.MarshalIndent(refvals, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	// Calculate aggregate and write to stdout
	if pcrConf.PrintAggregate {
		aggregate, err := tcg.PrecomputeAggregatePcrValue(refvals, pcrConf.HashAlg,
			pcrConf.AggregateHashAlg)
		if err != nil {
			return fmt.Errorf("failed to calculate aggregate PCR value")
		}

		data, err := json.MarshalIndent(aggregate, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	log.Info("Finished")

	return nil
}

func getConfig(cmd *cli.Command) (*ParsePcrsConf, error) {

	alg, err := internal.HashFromString(cmd.String(hashAlgFlag))
	if err != nil {
		return nil, fmt.Errorf("failed to parse %v: %w", hashAlgFlag, err)
	}

	aggAlg, err := internal.HashFromString(cmd.String(aggregateAlgFlag))
	if err != nil {
		return nil, fmt.Errorf("failed to parse %v: %w", aggregateAlgFlag, err)
	}

	c := &ParsePcrsConf{
		PrintAggregate:   cmd.Bool(printAggregateFlag),
		HashAlg:          alg,
		AggregateHashAlg: aggAlg,
	}
	return c, nil
}

func checkConfig(globConf *global.Config, parsePcrsConf *ParsePcrsConf) error {

	for _, mr := range globConf.Mrs {
		if mr > 23 {
			return fmt.Errorf("invalid PCR value: %v. Only 0-23 are allowed", mr)
		}
	}
	return nil
}

func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
