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

package sign

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var log = logrus.WithField("service", "metatool")

const (
	inFlag         = "in"
	outFlag        = "out"
	keysFlag       = "keys"
	x5csFlag       = "x5cs"
	prepareFlag    = "prepare"
	attachFlag     = "attach"
	tbsOutFlag     = "tbs-out"
	digestOutFlag  = "digest-out"
	signaturesFlag = "signatures"
)

var Command = &cli.Command{
	Name:  "sign",
	Usage: "sign metadata with private keys and certificate chains",
	Description: `Signs metadata with the keys given via --keys. Alternatively, the signatures can
	be created outside of metatool, e.g. with a key held in a KMS or HSM, in two steps:

1. --prepare writes the data to be signed for each certificate chain: --tbs-out the exact byte
   string to be signed, --digest-out its hash under the signature algorithm (not for Ed25519).

2. --attach adds the signatures given via --signatures and writes the signed metadata to --out.
   --in and --x5cs must be identical to step 1. ECDSA signatures must be ASN.1 DER encoded.

The signature algorithm is derived from the leaf certificate: ECDSA P-256/P-384/P-521 use
ES256/ES384/ES512, Ed25519 uses EdDSA, RSA 2048/3072/4096 uses RSASSA-PSS with SHA-256/384/512
and a salt length equal to the hash length (PS256/PS384/PS512).`,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     inFlag,
			Usage:    "path to input metadata as JSON or CBOR to be signed",
			Required: true,
		},
		&cli.StringFlag{
			Name:  outFlag,
			Usage: "path to the output file to save signed metadata",
		},
		&cli.StringFlag{
			Name: keysFlag,
			Usage: `paths to PEM encoded private keys (PKCS#8, SEC 1 or PKCS#1), comma-separated.
Supported are ECDSA P-256/P-384/P-521, Ed25519 and RSA 2048/3072/4096 (RSA-PSS). Each key must
match the leaf certificate of the corresponding chain`,
		},
		&cli.StringFlag{
			Name: x5csFlag,
			Usage: `paths to PEM encoded x509 certificate chains. Chains colon-separated, certs
within a chain comma-separated (e.g. leaf1,intermediate1,ca1:leaf2,intermediate2,ca2)`,
			Required: true,
		},
		&cli.BoolFlag{
			Name:  prepareFlag,
			Usage: "write the data to be signed by an external signer instead of signing",
		},
		&cli.BoolFlag{
			Name:  attachFlag,
			Usage: "create the signed metadata from signatures created by an external signer",
		},
		&cli.StringFlag{
			Name: tbsOutFlag,
			Usage: `with --prepare: paths to write the data to be signed to, one per certificate
chain, comma-separated`,
		},
		&cli.StringFlag{
			Name: digestOutFlag,
			Usage: `with --prepare: paths to write the digest of the data to be signed to, one per
certificate chain, comma-separated. Not available for Ed25519`,
		},
		&cli.StringFlag{
			Name:  signaturesFlag,
			Usage: "with --attach: paths to the per-chain signatures, comma-separated",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		if err := checkFlags(cmd); err != nil {
			return err
		}

		data, err := os.ReadFile(cmd.String(inFlag))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		chainsPem, err := LoadCertChains(cmd.String(x5csFlag))
		if err != nil {
			return fmt.Errorf("failed to load certificate chains: %w", err)
		}

		if cmd.Bool(prepareFlag) {
			return prepare(cmd, data, chainsPem)
		}

		var signedData []byte
		if cmd.Bool(attachFlag) {
			log.Infof("Attaching signatures to %v", cmd.String(inFlag))
			sigs, err := LoadFiles(cmd.String(signaturesFlag))
			if err != nil {
				return fmt.Errorf("failed to load signatures: %w", err)
			}
			signedData, err = Attach(data, sigs, chainsPem)
			if err != nil {
				return fmt.Errorf("failed to attach signatures: %w", err)
			}
		} else {
			log.Infof("Signing %v", cmd.String(inFlag))
			keysPem, err := LoadFiles(cmd.String(keysFlag))
			if err != nil {
				return fmt.Errorf("failed to load keys: %w", err)
			}
			signedData, err = Sign(data, keysPem, chainsPem)
			if err != nil {
				return fmt.Errorf("failed to sign data: %w", err)
			}
		}

		outFile := cmd.String(outFlag)
		log.Infof("Writing %v", outFile)
		err = os.WriteFile(outFile, signedData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}

		return nil
	},
}

// checkFlags checks that exactly the flags of the selected mode are set
func checkFlags(cmd *cli.Command) error {
	mode, allowed, required := "signing", []string{keysFlag, outFlag}, []string{keysFlag, outFlag}
	switch {
	case cmd.Bool(prepareFlag) && cmd.Bool(attachFlag):
		return fmt.Errorf("--%v and --%v are mutually exclusive", prepareFlag, attachFlag)
	case cmd.Bool(prepareFlag):
		mode, allowed, required = "--"+prepareFlag, []string{tbsOutFlag, digestOutFlag}, nil
		if !cmd.IsSet(tbsOutFlag) && !cmd.IsSet(digestOutFlag) {
			return fmt.Errorf("--%v requires --%v or --%v", prepareFlag, tbsOutFlag, digestOutFlag)
		}
	case cmd.Bool(attachFlag):
		mode, allowed, required = "--"+attachFlag, []string{signaturesFlag, outFlag}, []string{signaturesFlag, outFlag}
	}
	for _, f := range required {
		if !cmd.IsSet(f) {
			return fmt.Errorf("%v requires --%v", mode, f)
		}
	}
	for _, f := range []string{keysFlag, outFlag, tbsOutFlag, digestOutFlag, signaturesFlag} {
		if cmd.IsSet(f) && !slices.Contains(allowed, f) {
			return fmt.Errorf("--%v cannot be used with %v", f, mode)
		}
	}
	return nil
}

func prepare(cmd *cli.Command, data []byte, chainsPem [][][]byte) error {
	log.Infof("Preparing %v for external signing", cmd.String(inFlag))

	tbs, err := Prepare(data, chainsPem)
	if err != nil {
		return fmt.Errorf("failed to prepare data: %w", err)
	}

	// Collect all output files before writing any of them
	files := map[string][]byte{}
	collect := func(flag string, contents [][]byte) error {
		paths := strings.Split(cmd.String(flag), ",")
		if len(paths) != len(contents) {
			return fmt.Errorf("got %v --%v paths for %v certificate chains", len(paths), flag, len(contents))
		}
		for i, path := range paths {
			if _, ok := files[path]; ok {
				return fmt.Errorf("path %v is used more than once", path)
			}
			files[path] = contents[i]
		}
		return nil
	}

	if cmd.IsSet(tbsOutFlag) {
		contents := make([][]byte, 0, len(tbs))
		for _, t := range tbs {
			contents = append(contents, t.Data)
		}
		if err := collect(tbsOutFlag, contents); err != nil {
			return err
		}
	}
	if cmd.IsSet(digestOutFlag) {
		contents := make([][]byte, 0, len(tbs))
		for i, t := range tbs {
			if t.Digest == nil {
				return fmt.Errorf("signer %v uses Ed25519, which signs the data without prior hashing. Use --%v",
					i, tbsOutFlag)
			}
			contents = append(contents, t.Digest)
		}
		if err := collect(digestOutFlag, contents); err != nil {
			return err
		}
	}

	for path, content := range files {
		log.Infof("Writing %v", path)
		if err := os.WriteFile(path, content, 0644); err != nil {
			return fmt.Errorf("failed to write %v: %w", path, err)
		}
	}

	return nil
}
