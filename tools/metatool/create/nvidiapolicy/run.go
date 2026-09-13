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

package nvidiapolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
)

var log = logrus.WithField("service", "metatool")

const (
	vbiosMinVersionFlag      = "vbios-min-version"
	driverMinVersionFlag     = "driver-min-version"
	allowedArchsFlag         = "allowed-architectures"
	enforceNonceFlag         = "enforce-nonce"
	requireOcspForRimsFlag   = "require-ocsp-for-rims"
	deviceCaFingerprintsFlag = "device-ca-fingerprints"
	rimCaFingerprintsFlag    = "rim-ca-fingerprints"

	requireSuppEvidenceFlag = "require-supplemental-evidence"
	allowedUuidsFlag        = "allowed-uuids"
	deniedUuidsFlag         = "denied-uuids"
	inforomOemMinFlag       = "inforom-oem-min-version"
	inforomEccMinFlag       = "inforom-ecc-min-version"
	inforomPowerMinFlag     = "inforom-power-min-version"
	inforomImageMinFlag     = "inforom-image-min-version"
	inforomChecksumsFlag    = "inforom-config-checksums"
	requireInforomValidFlag = "require-inforom-valid"
	gspFirmwareMinFlag      = "gsp-firmware-min-version"
	requireGspEnabledFlag   = "require-gsp-enabled"
	requireGspDefaultFlag   = "require-gsp-default"
	migCurrentModeFlag      = "mig-current-mode"
	migPendingModeFlag      = "mig-pending-mode"
)

// extraSecurityFlags lists the flags which populate the nested extra security policy.
// The nested policy is only emitted when at least one of them is set.
var extraSecurityFlags = []string{
	requireSuppEvidenceFlag,
	allowedUuidsFlag,
	deniedUuidsFlag,
	inforomOemMinFlag,
	inforomEccMinFlag,
	inforomPowerMinFlag,
	inforomImageMinFlag,
	inforomChecksumsFlag,
	requireInforomValidFlag,
	gspFirmwareMinFlag,
	requireGspEnabledFlag,
	requireGspDefaultFlag,
	migCurrentModeFlag,
	migPendingModeFlag,
}

var Command = &cli.Command{
	Name: "nvidia-policy",
	Usage: "create an NVIDIA CC GPU policy. The flags below the architecture allowlist" +
		" configure the supplemental checks, which require the prover to run with" +
		" extended checks enabled",
	Flags: append(create.OutputFlags,
		&cli.StringFlag{
			Name:     deviceCaFingerprintsFlag,
			Required: true,
			Usage: "allowlist of SHA-256 fingerprints of the NVIDIA device identity root CAs," +
				" hex encoded, comma-separated",
		},
		&cli.StringFlag{
			Name:     rimCaFingerprintsFlag,
			Required: true,
			Usage: "allowlist of SHA-256 fingerprints of the NVIDIA RIM signing root CAs," +
				" hex encoded, comma-separated",
		},
		&cli.StringFlag{
			Name:  vbiosMinVersionFlag,
			Usage: "vbios minimum version",
		},
		&cli.StringFlag{
			Name:  driverMinVersionFlag,
			Usage: "driver minimum version",
		},
		&cli.StringFlag{
			Name: allowedArchsFlag,
			Usage: "allowlist of GPU architecture names, comma-separated (HOPPER, BLACKWELL)," +
				" omit to permit all known architectures",
		},
		&cli.BoolFlag{
			Name:  enforceNonceFlag,
			Usage: "reject reports which do not echo the supplied nonce",
		},
		&cli.BoolFlag{
			Name:  requireOcspForRimsFlag,
			Usage: "reject RIMs whose signing chain has no valid OCSP response",
		},
		&cli.BoolFlag{
			Name:  requireSuppEvidenceFlag,
			Usage: "require the unsigned supplemental GPU measurements to be present",
		},
		&cli.StringFlag{
			Name:  allowedUuidsFlag,
			Usage: "allowlist of GPU UUIDs, comma-separated, omit to permit any device",
		},
		&cli.StringFlag{
			Name:  deniedUuidsFlag,
			Usage: "denylist of GPU UUIDs, comma-separated, rejected even if all other checks pass",
		},
		&cli.StringFlag{
			Name:  inforomOemMinFlag,
			Usage: "minimum inforom OEM object version",
		},
		&cli.StringFlag{
			Name:  inforomEccMinFlag,
			Usage: "minimum inforom ECC object version",
		},
		&cli.StringFlag{
			Name:  inforomPowerMinFlag,
			Usage: "minimum inforom power object version",
		},
		&cli.StringFlag{
			Name:  inforomImageMinFlag,
			Usage: "minimum inforom image version (e.g. G520.0200.00.04)",
		},
		&cli.StringFlag{
			Name:  inforomChecksumsFlag,
			Usage: "allowlist of inforom configuration checksums, comma-separated",
		},
		&cli.BoolFlag{
			Name: requireInforomValidFlag,
			Usage: "require the inforom to be reported as valid, or as invalid with" +
				" =false, omit to not check it",
		},
		&cli.StringFlag{
			Name:  gspFirmwareMinFlag,
			Usage: "minimum GSP firmware version",
		},
		&cli.BoolFlag{
			Name: requireGspEnabledFlag,
			Usage: "require GSP firmware to be enabled, or to be disabled with =false," +
				" omit to not check it",
		},
		&cli.BoolFlag{
			Name: requireGspDefaultFlag,
			Usage: "require GSP firmware to be in its default mode, or to not be with" +
				" =false, omit to not check it",
		},
		&cli.UintFlag{
			Name:  migCurrentModeFlag,
			Usage: "expected current MIG mode, omit to not check it",
		},
		&cli.UintFlag{
			Name:  migPendingModeFlag,
			Usage: "expected pending MIG mode, omit to not check it",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		log.Info("Creating NVIDIA GPU policy")

		p := ar.NvidiaPolicy{
			VbiosMinVersion:      cmd.String(vbiosMinVersionFlag),
			DriverMinVersion:     cmd.String(driverMinVersionFlag),
			EnforceNonce:         cmd.Bool(enforceNonceFlag),
			RequireOCSPForRIMs:   cmd.Bool(requireOcspForRimsFlag),
			DeviceCaFingerprints: splitList(cmd.String(deviceCaFingerprintsFlag)),
			RimCaFingerprints:    splitList(cmd.String(rimCaFingerprintsFlag)),
		}

		if len(p.DeviceCaFingerprints) == 0 {
			return fmt.Errorf("%v must contain at least one fingerprint", deviceCaFingerprintsFlag)
		}
		if len(p.RimCaFingerprints) == 0 {
			return fmt.Errorf("%v must contain at least one fingerprint", rimCaFingerprintsFlag)
		}
		for flag, fingerprints := range map[string][]string{
			deviceCaFingerprintsFlag: p.DeviceCaFingerprints,
			rimCaFingerprintsFlag:    p.RimCaFingerprints,
		} {
			for _, f := range fingerprints {
				d, err := hex.DecodeString(f)
				if err != nil {
					return fmt.Errorf("%v: %q is not hex encoded: %w", flag, f, err)
				}
				if len(d) != sha256.Size {
					return fmt.Errorf("%v: %q is %v bytes, expected a %v byte SHA-256 digest",
						flag, f, len(d), sha256.Size)
				}
			}
		}

		if cmd.IsSet(allowedArchsFlag) {
			// The verifier compares against the architecture name as it appears in the
			// evidence, which is upper case. Normalising here keeps a lower case
			// spelling from producing an allowlist that matches nothing
			for _, a := range splitList(cmd.String(allowedArchsFlag)) {
				p.AllowedArchitectures = append(p.AllowedArchitectures, strings.ToUpper(a))
			}
		}

		if extra := extraSecurityPolicy(cmd); extra != nil {
			p.ExtraSecurityPolicy = extra
		}

		return create.Output(cmd, &p)
	},
}

// extraSecurityPolicy assembles the nested supplemental policy, or returns nil if the
// caller set none of its flags.
func extraSecurityPolicy(cmd *cli.Command) *ar.NvidiaExtraSecurityPolicy {
	if !slices.ContainsFunc(extraSecurityFlags, cmd.IsSet) {
		return nil
	}

	e := &ar.NvidiaExtraSecurityPolicy{
		RequireSupplementalEvidence: cmd.Bool(requireSuppEvidenceFlag),
		AllowedUUIDs:                splitList(cmd.String(allowedUuidsFlag)),
		DeniedUUIDs:                 splitList(cmd.String(deniedUuidsFlag)),
		InforomOemMinVersion:        cmd.String(inforomOemMinFlag),
		InforomEccMinVersion:        cmd.String(inforomEccMinFlag),
		InforomPowerMinVersion:      cmd.String(inforomPowerMinFlag),
		InforomImageMinVersion:      cmd.String(inforomImageMinFlag),
		InforomConfigChecksums:      splitList(cmd.String(inforomChecksumsFlag)),
		GspFirmwareMinVersion:       cmd.String(gspFirmwareMinFlag),
	}

	// The remaining fields are pointers so that the policy can distinguish "not
	// checked" from "checked and expected to be false or zero".
	if cmd.IsSet(requireInforomValidFlag) {
		e.RequireInforomValid = new(cmd.Bool(requireInforomValidFlag))
	}
	if cmd.IsSet(requireGspEnabledFlag) {
		e.RequireGspEnabled = new(cmd.Bool(requireGspEnabledFlag))
	}
	if cmd.IsSet(requireGspDefaultFlag) {
		e.RequireGspDefault = new(cmd.Bool(requireGspDefaultFlag))
	}
	if cmd.IsSet(migCurrentModeFlag) {
		e.MigCurrentModeExpected = new(uint32(cmd.Uint(migCurrentModeFlag)))
	}
	if cmd.IsSet(migPendingModeFlag) {
		e.MigPendingModeExpected = new(uint32(cmd.Uint(migPendingModeFlag)))
	}

	return e
}

// splitList splits a comma-separated flag value. Empty entries are dropped.
func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
