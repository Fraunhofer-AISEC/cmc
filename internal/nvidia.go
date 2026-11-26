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

package internal

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type InforomObject int32

const (
	INFOROM_OEM InforomObject = iota
	INFOROM_ECC
	INFOROM_POWER
)

// NvidiaDeviceUnsignedEvidence holds measurements the driver queries from NVML which are
// not covered by the signed GPU attestation report. They are only collected when the
// driver runs with extended checks enabled, and are only evaluated against an
// ar.NvidiaExtraSecurityPolicy. InforomConfigChecksum is the 32-bit checksum formatted as
// lowercase hex with 0x prefix and eight digits, e.g. 0x1a2b3c4d.
type NvidiaDeviceUnsignedEvidence struct {
	UUID                  string `json:"uuid" cbor:"0,keyasint"`
	InforomOemVersion     string `json:"inforomOemVersion" cbor:"1,keyasint"`
	InforomEccVersion     string `json:"inforomEccVersion" cbor:"2,keyasint"`
	InforomPowerVersion   string `json:"inforomPowerVersion" cbor:"3,keyasint"`
	InforomImageVersion   string `json:"inforomImageVersion" cbor:"4,keyasint"`
	InforomConfigChecksum string `json:"inforomConfigChecksum" cbor:"5,keyasint"`
	GspFirmwareVersion    string `json:"gspFirmwareVersion" cbor:"6,keyasint"`
	GspFirmwareIsEnabled  bool   `json:"gspFirmwareIsEnabled" cbor:"7,keyasint"`
	GspFirmwareDefault    bool   `json:"gspFirmwareDefault" cbor:"8,keyasint"`
	InforomIsValid        bool   `json:"inforomIsValid" cbor:"9,keyasint"`
	MigCurrentMode        uint32 `json:"migCurrentMode" cbor:"10,keyasint"`
	MigPendingMode        uint32 `json:"migPendingMode" cbor:"11,keyasint"`
}

// NvidiaGPUEvidence is the payload the NVIDIA driver CBOR-encodes into ar.Evidence.Data for a
// single GPU.
type NvidiaGPUEvidence struct {
	Architecture            string                        `json:"architecture" cbor:"0,keyasint"`
	UUID                    string                        `json:"uuid" cbor:"1,keyasint"`
	SignedAttestationReport string                        `json:"signedAttestationReport" cbor:"2,keyasint"`
	Certificates            string                        `json:"certificates" cbor:"3,keyasint"`
	UnsignedMeasurements    *NvidiaDeviceUnsignedEvidence `json:"unsignedMeasurements,omitempty" cbor:"4,keyasint,omitempty"`
}

// ParseCertChain accepts either a string or a []byte using a generic constraint.
func ParseCertChain[T string | []byte](certChain T) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Convert T to []byte. The compiler allows this because both
	// string and []byte can be explicitly cast to []byte.
	certBytes := []byte(certChain)

	for {
		// Decode the next PEM block
		block, rest := pem.Decode(certBytes)
		if block == nil {
			break
		}

		// Check if the block is actually a certificate
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		// Move to the next block in the chain
		certBytes = rest
	}

	if len(certs) == 0 {
		return nil, errors.New("no valid certificates found in the provided data")
	}

	return certs, nil
}
