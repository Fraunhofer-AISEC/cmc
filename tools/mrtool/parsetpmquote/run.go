// Copyright (c) 2026 Fraunhofer AISEC
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

package parsetpmquote

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	inFlag     = "in"
	formatFlag = "format"

	formatAuto  = "auto"
	formatRaw   = "raw"
	formatAzure = "azure"

	// TPM_GENERATED_VALUE. Every TPMS_ATTEST produced by a genuine TPM starts
	// with this constant (see TPM 2.0 Library, Part 2, "TPM_GENERATED").
	tpmGenerated uint32 = 0xff544347
)

var (
	log = logrus.WithField("service", "mrtool")
)

var Command = &cli.Command{
	Name: "tpm-quote",
	Usage: "decodes and prints the fields of a TPM quote (TPMS_ATTEST). Accepts the TPMS_ATTEST " +
		"format as well as the [quote|sig] blob produced by 'azuretool get-vtpm-quote'. The " +
		"format is auto-detected from the TPM_GENERATED magic",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     inFlag,
			Usage:    "input file containing the TPM quote",
			Required: true,
		},
		&cli.StringFlag{
			Name: formatFlag,
			Usage: "force input format ('auto' inspects the magic; 'raw' expects a bare " +
				"TPMS_ATTEST, 'azure' expects the [quote|sig] blob written by azuretool)",
			Value: formatAuto,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		if err := run(cmd); err != nil {
			return fmt.Errorf("failed to parse tpm quote: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	if _, err := global.GetConfig(cmd); err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	inPath := cmd.String(inFlag)
	data, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("failed to read input file %q: %w", inPath, err)
	}

	quote, sig, err := extractQuote(data, cmd.String(formatFlag))
	if err != nil {
		return err
	}

	ad, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		return fmt.Errorf("failed to decode TPMS_ATTEST: %w", err)
	}

	printAttestationData(ad, sig)

	return nil
}

// extractQuote returns the raw TPMS_ATTEST bytes (and optionally the signature)
// from either a bare quote blob or an azuretool-framed
// [qLen|quote|sLen|sig] blob. When format is "auto", the layout is inferred
// from the position of the TPM_GENERATED_VALUE magic.
func extractQuote(data []byte, format string) (quote, sig []byte, err error) {
	switch format {
	case formatRaw:
		return data, nil, nil
	case formatAzure:
		return unpackAzureFramed(data)
	case formatAuto, "":
		if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == tpmGenerated {
			log.Debug("Detected raw TPMS_ATTEST format")
			return data, nil, nil
		}
		if len(data) >= 8 && binary.BigEndian.Uint32(data[4:8]) == tpmGenerated {
			log.Debug("Detected azuretool-framed quote+signature format")
			return unpackAzureFramed(data)
		}
		return nil, nil, fmt.Errorf(
			"could not detect quote format: TPM_GENERATED magic 0x%08x not at offset 0 or 4. "+
				"Use --%s to override", tpmGenerated, formatFlag)
	default:
		return nil, nil, fmt.Errorf("unknown format %q (want %q, %q, or %q)",
			format, formatAuto, formatRaw, formatAzure)
	}
}

// unpackAzureFramed mirrors the framing written by azuretool's encodeQuoteBlob:
// 4-byte BE quote length, quote bytes, 4-byte BE signature length, signature.
func unpackAzureFramed(data []byte) (quote, sig []byte, err error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("azure quote blob too short for quote length prefix")
	}
	qLen := binary.BigEndian.Uint32(data[:4])
	if uint64(len(data)) < 4+uint64(qLen)+4 {
		return nil, nil, fmt.Errorf("azure quote blob too short for quote of length %d", qLen)
	}
	quote = data[4 : 4+qLen]
	sigOff := 4 + qLen
	sLen := binary.BigEndian.Uint32(data[sigOff : sigOff+4])
	if uint64(len(data)) != uint64(sigOff)+4+uint64(sLen) {
		return nil, nil, fmt.Errorf(
			"azure quote blob length %d does not match framed lengths (quote %d + sig %d)",
			len(data), qLen, sLen)
	}
	sig = data[sigOff+4 : sigOff+4+sLen]
	return quote, sig, nil
}

func printAttestationData(ad *tpm2.AttestationData, sig []byte) {
	log.Info("TPMS_ATTEST:")
	log.Infof("\tMagic           : 0x%08x", ad.Magic)
	log.Infof("\tType            : 0x%04x (%s)", uint16(ad.Type), attestTypeString(ad.Type))
	log.Infof("\tQualifiedSigner : %s", nameString(ad.QualifiedSigner))
	log.Infof("\tExtraData/Nonce : %s", hex.EncodeToString(ad.ExtraData))
	log.Infof("\tFirmwareVersion : 0x%016x", ad.FirmwareVersion)
	log.Info("\tClockInfo:")
	log.Infof("\t\tClock        : %d", ad.ClockInfo.Clock)
	log.Infof("\t\tResetCount   : %d", ad.ClockInfo.ResetCount)
	log.Infof("\t\tRestartCount : %d", ad.ClockInfo.RestartCount)
	log.Infof("\t\tSafe         : %d", ad.ClockInfo.Safe)

	if q := ad.AttestedQuoteInfo; q != nil {
		log.Info("\tAttestedQuoteInfo:")
		log.Infof("\t\tPCRSelection Hash : 0x%04x (%s)",
			uint16(q.PCRSelection.Hash), hashAlgString(q.PCRSelection.Hash))
		log.Infof("\t\tPCRSelection PCRs : %v", q.PCRSelection.PCRs)
		log.Infof("\t\tPCRDigest         : %s", hex.EncodeToString(q.PCRDigest))
	}

	if sig != nil {
		log.Infof("\tSignature (%d bytes) : %s", len(sig), hex.EncodeToString(sig))
	}
}

func attestTypeString(t tpmutil.Tag) string {
	switch t {
	case tpm2.TagAttestQuote:
		return "TPM_ST_ATTEST_QUOTE"
	case tpm2.TagAttestCertify:
		return "TPM_ST_ATTEST_CERTIFY"
	case tpm2.TagAttestCreation:
		return "TPM_ST_ATTEST_CREATION"
	default:
		return "unknown"
	}
}

func hashAlgString(h tpm2.Algorithm) string {
	switch h {
	case tpm2.AlgSHA1:
		return "SHA1"
	case tpm2.AlgSHA256:
		return "SHA256"
	case tpm2.AlgSHA384:
		return "SHA384"
	case tpm2.AlgSHA512:
		return "SHA512"
	default:
		return "unknown"
	}
}

func nameString(n tpm2.Name) string {
	if n.Handle != nil {
		return fmt.Sprintf("handle=0x%08x", uint32(*n.Handle))
	}
	if n.Digest != nil {
		return fmt.Sprintf("digest[alg=0x%04x]=%s",
			uint16(n.Digest.Alg), hex.EncodeToString(n.Digest.Value))
	}
	return "<empty>"
}
