// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

//go:build amd64 && (!nodefaults || snp)

package snpdriver

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-sev-guest/client"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "snpdriver")

const (
	akChainFile = "snp_ak_chain.pem"
)

var (
	VlekUuid = []byte{0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1}
)

// Snp is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Snp struct {
	*drivers.DriverConfig
	akChain  []*x509.Certificate // SNP VCEK / VLEK certificate chain
	endorser drivers.SnpEndorser
}

type SnpCertTableEntry struct {
	Uuid   [16]byte
	Offset uint32
	Length uint32
}

// Name returns the name of the driver
func (s *Snp) Name() string {
	return "SNP driver"
}

// Init initializaes the SNP driver with the specifified configuration
func (snp *Snp) Init(c *drivers.DriverConfig) error {
	var err error

	// Initial checks
	if snp == nil {
		return errors.New("internal error: SNP object is nil")
	}
	if c.Endorsers == nil {
		return fmt.Errorf("missing endorser provider")
	}

	endorser, ok := c.Endorsers.Snp()
	if !ok {
		return fmt.Errorf("snp endorser not configured")
	}
	snp.endorser = endorser

	snp.DriverConfig = c

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create directory for internal data '%v': %w",
					c.StoragePath, err)
			}
		}
	}

	if provisioningRequired(c.StoragePath) {
		log.Info("Performing SNP provisioning")

		err = snp.provision()
		if err != nil {
			return fmt.Errorf("failed to provision snp driver: %w", err)
		}

		if c.StoragePath != "" {
			err = snp.saveCredentials()
			if err != nil {
				return fmt.Errorf("failed to save SNP credentials: %w", err)
			}
		}
	} else {
		err = snp.loadCredentials()
		if err != nil {
			return fmt.Errorf("failed to load SNP credentials: %w", err)
		}
	}

	return nil
}

func (snp *Snp) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debug("Collecting SNP evidence")

	if snp == nil {
		return nil, errors.New("internal error: SNP object is nil")
	}

	data, err := GetReport(nonce, snp.Vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP Measurement: %w", err)
	}

	evidences := []ar.Evidence{
		{
			Type: ar.TYPE_EVIDENCE_SNP,
			Data: data,
		},
	}

	return evidences, nil
}

func (snp *Snp) GetCollateral() ([]ar.Collateral, error) {

	return []ar.Collateral{
		{
			Type:  ar.TYPE_EVIDENCE_SNP,
			Certs: internal.WriteCertsDer(snp.akChain),
		},
	}, nil
}

func GetReport(nonce []byte, vmpl int) ([]byte, error) {

	if len(nonce) > 64 {
		return nil, errors.New("user Data must be at most 64 bytes")
	}

	log.Debugf("Generating SNP attestation report on VMPL %v with nonce: %v", vmpl,
		hex.EncodeToString(nonce))

	qp, err := client.GetLeveledQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %w", err)
	}

	var ud [64]byte
	copy(ud[:], nonce)
	buf, err := qp.GetRawQuoteAtLevel(ud, uint(vmpl))
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP attestation report")
	}

	log.Debug("Generated SNP attestation report")

	return buf, nil
}

func (snp *Snp) UpdateCerts() error {
	var err error

	// Initial checks
	if snp == nil {
		return errors.New("internal error: snp object is nil")
	}

	log.Info("Updating snp certificates")

	err = snp.provision()
	if err != nil {
		return fmt.Errorf("failed to provision snp driver: %w", err)
	}

	if snp.StoragePath != "" {
		err = snp.saveCredentials()
		if err != nil {
			return fmt.Errorf("failed to save snp credentials: %w", err)
		}
	}

	return nil
}

func getVlek(vmpl int) ([]byte, error) {

	log.Debugf("Fetching VLEK via extended attestation report request on VMPL %v", vmpl)

	d, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/sev-guest")
	}
	defer d.Close()

	//lint:ignore SA1019 will be updated later
	_, certs, err := client.GetRawExtendedReportAtVmpl(d, [64]byte{0}, vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP attestation report")
	}

	log.Debugf("Fetched extended SNP attestation report with certs length %v", len(certs))

	b := bytes.NewBuffer(certs)
	for {
		log.Debug("Parsing cert table entry..")
		var entry SnpCertTableEntry
		err = binary.Read(b, binary.LittleEndian, &entry)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cert table entry: %w", err)
		}

		if entry == (SnpCertTableEntry{}) {
			log.Debugf("Reached last (zero) SNP cert table entry")
			break
		}

		log.Debugf("Found cert table entry with UUID %v", hex.EncodeToString(entry.Uuid[:]))

		if bytes.Equal(entry.Uuid[:], VlekUuid) {
			log.Debugf("Found VLEK offset %v length %v", entry.Offset, entry.Length)
			return certs[entry.Offset : entry.Offset+entry.Length], nil
		}
	}

	return nil, errors.New("could not find VLEK in certificates")
}

func (snp *Snp) provision() error {

	// Fetch SNP certificate chain for VCEK/VLEK (SNP Attestation Key)
	err := snp.fetchAk()
	if err != nil {
		return fmt.Errorf("failed to get SNP cert chain: %w", err)
	}

	return nil
}

func (snp *Snp) fetchAk() error {

	// Generate random nonce
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Fetch the SNP attestation report signing key. Usually, this is the VCEK. However,
	// in cloud environments, the CSP might disable VCEK usage, instead the VLEK is used.
	// Fetch an initial attestation report to determine which key is used.
	arRaw, err := GetReport(nonce, snp.Vmpl)
	if err != nil {
		return fmt.Errorf("failed to get SNP report: %w", err)
	}
	s, err := verifier.DecodeSnpReport(arRaw)
	if err != nil {
		return fmt.Errorf("failed to decode SNP report: %w", err)
	}

	// Verify nonce
	if !bytes.Equal(nonce, s.ReportData[:]) {
		return fmt.Errorf("failed to verify SNP report nonce (expected %v, got %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
	}
	log.Debugf("Successfully decoded attestation report and verified nonce")

	akType, err := internal.GetAkType(s.KeySelection)
	if err != nil {
		return fmt.Errorf("could not determine SNP attestation report attestation key")
	}

	log.Debugf("Fetched Chip ID from attestation report: %x", s.ChipId[:])

	codeName := verifier.GetSnpCodeName(s.CpuFamilyId, s.CpuModelId)

	log.Debugf("Fetched EPYC code name from attestation report: %q", codeName)

	var akCert *x509.Certificate
	switch akType {
	case internal.VCEK:
		// VCEK is used, request enrollment for SNP chip ID and TCB
		log.Debug("Enrolling VCEK")
		akCert, err = snp.endorser.GetSnpVcek(codeName, s.ChipId[:], s.CurrentTcb)
		if err != nil {
			return fmt.Errorf("failed to enroll SNP: %w", err)
		}
	case internal.VLEK:
		// VLEK is used, in this case we fetch the VLEK from the host
		vlek, err := getVlek(snp.Vmpl)
		if err != nil {
			return fmt.Errorf("failed to fetch VLEK: %w", err)
		}
		log.Debug("Parsing VLEK")
		akCert, err = x509.ParseCertificate(vlek)
		if err != nil {
			return fmt.Errorf("failed to parse VLEK")
		}
		log.Debugf("Successfully parsed VLEK CN=%v", akCert.Subject.CommonName)
	default:
		return fmt.Errorf("internal error: signing cert not initialized")
	}

	// Fetch intermediate CAs and CA depending on signing key (VLEK / VCEK)
	log.Debugf("Fetching SNP CA for %v", akType.String())
	ca, err := snp.endorser.GetSnpCa(codeName, akType)
	if err != nil {
		return fmt.Errorf("failed to get SNP CA from EST server: %w", err)
	}

	snp.akChain = append([]*x509.Certificate{akCert}, ca...)

	return nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, akChainFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}

	log.Info("SNP Provisioning NOT REQUIRED")

	return false
}

func (snp *Snp) loadCredentials() error {

	data, err := os.ReadFile(path.Join(snp.StoragePath, akChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", snp.StoragePath, err)
	}
	snp.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(snp.akChain))

	return nil
}

func (snp *Snp) saveCredentials() error {
	akchainPem := make([]byte, 0)
	for _, cert := range snp.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(snp.StoragePath, akChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(snp.StoragePath, akChainFile), err)
	}

	return nil
}
