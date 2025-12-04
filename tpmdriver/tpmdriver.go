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

package tpmdriver

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	"go.mozilla.org/pkcs7"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/ima"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
)

// Tpm is a structure that implements the Measure method
// of the attestation report Measurer interface
type Tpm struct {
	mu           sync.Mutex
	pcrs         []int
	ikChain      []*x509.Certificate
	akChain      []*x509.Certificate
	biosLog      bool
	imaLog       bool
	imaPcr       int
	excludedPcrs []int
	ctrLog       bool
	ctrPcr       int
	ctrLogFile   string
	serializer   ar.Serializer
}

const (
	akchainFile = "tpm_ak_chain.pem"
	ikchainFile = "tpm_ik_chain.pem"
	akFile      = "tpm_ak_encrypted.json"
	ikFile      = "tpm_ik_encrypted.json"

	DEFAULT_BINARY_BIOS_MEASUREMENTS = "/sys/kernel/security/tpm0/binary_bios_measurements"
	DEFAULT_EVENT_TYPE               = "TPM Measurement"

	tpmResourceManagerPath = "/dev/tpmrm0"
	tpmDevicePath          = "/dev/tpm0"
)

var (
	TPM *attest.TPM = nil
	ak  *attest.AK  = nil
	ik  *attest.Key = nil
	ek  []attest.EK
)

var log = logrus.WithField("service", "tpmdriver")

// Name returns the name of the driver
func (t *Tpm) Name() string {
	return "TPM driver"
}

// Init opens and initializes a TPM object, checks if provosioning is
// required and if so, provisions the TPM
func (t *Tpm) Init(c *ar.DriverConfig) error {

	// Initial checks
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	t.imaLog = c.Ima
	t.imaPcr = c.ImaPcr
	t.excludedPcrs = c.ExcludePcrs
	t.biosLog = c.MeasurementLog
	t.serializer = c.Serializer
	t.ctrLog = c.Ctr && strings.EqualFold(c.CtrDriver, "tpm")
	t.ctrLogFile = c.CtrLog
	t.ctrPcr = c.CtrPcr

	// Check if serializer is initialized
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create local storage '%v': %v", c.StoragePath, err)
			}
		}
	}

	// Check if the TPM is provisioned. If provisioned, load the AK and IK key.
	// Otherwise perform credential activation with provisioning server and then load the keys
	provisioningRequired, err := IsTpmProvisioningRequired(c.StoragePath)
	if err != nil {
		return fmt.Errorf("failed to check if TPM is provisioned: %w", err)
	}

	err = OpenTpm()
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}

	// Determine if the system is an SRTM or DRTM system to include the
	// respective PCRs into the TPM quote
	t.pcrs, err = getQuotePcrs(t)
	if err != nil {
		return fmt.Errorf("failed to determine TPM Quote PCRs: %w", err)
	}

	if provisioningRequired {

		log.Info("Provisioning TPM (might take a while)..")

		err = t.provision(c)
		if err != nil {
			return fmt.Errorf("failed to provision TPM: %w", err)
		}

		if c.StoragePath != "" {
			err = t.saveCredentials(c.StoragePath)
			if err != nil {
				return fmt.Errorf("failed to save TPM data: %w", err)
			}
		}

	} else {
		err = t.loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load TPM keys: %w", err)
		}
	}

	name, err := GetAkQualifiedName()
	if err != nil {
		return fmt.Errorf("failed to get AK qualified name: %w", err)
	}
	log.Debugf("Using AK with qualified name: %v", hex.EncodeToString(name))

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (t *Tpm) Measure(nonce []byte) ([]ar.Measurement, error) {

	log.Debug("Collecting TPM measurements")

	if t == nil {
		return nil, fmt.Errorf("internal error: tpm object not initialized")
	}
	if len(t.pcrs) == 0 {
		return nil, fmt.Errorf("TPM measurement does not contain any PCRs")
	}

	log.Debugf("Collecting TPM Quote for PCRs %v",
		strings.Trim(strings.Join(strings.Fields(fmt.Sprint(t.pcrs)), ","), "[]"))

	attestPcrs, quote, err := t.GetMeasurement(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM Measurement: %w", err)
	}
	pcrs := map[int][]byte{}
	for _, attestPcr := range attestPcrs {
		pcrs[attestPcr.Index] = attestPcr.Digest
	}

	artifacts, err := GetEventLogs(t.serializer, t.biosLog, t.imaLog, t.ctrLog,
		t.pcrs, t.imaPcr, t.ctrPcr, t.ctrLogFile, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get event logs: %w", err)
	}

	tm := ar.Measurement{
		Type:      "TPM Measurement",
		Evidence:  quote.Quote,
		Signature: quote.Signature,
		Certs:     internal.WriteCertsDer(t.akChain),
		Artifacts: artifacts,
	}

	for _, elem := range tm.Artifacts {
		for _, event := range elem.Events {
			log.Tracef("PCR%v %v: %v", elem.Index, elem.Type, hex.EncodeToString(event.Sha256))
		}
	}
	log.Debug("Quote: ", hex.EncodeToString(tm.Evidence))
	log.Debug("Signature: ", hex.EncodeToString(tm.Signature))

	return []ar.Measurement{tm}, nil
}

func (t *Tpm) Lock() error {
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	log.Trace("Trying to get lock for TPM")
	t.mu.Lock()
	log.Trace("Got lock for TPM")
	return nil
}

func (t *Tpm) Unlock() error {
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	log.Trace("Releasing TPM Lock")
	t.mu.Unlock()
	log.Trace("Released TPM Lock")
	return nil
}

// GetKeyHandles returns private and public key handles as a generic crypto interface
func (t *Tpm) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {

	if t == nil {
		return nil, nil, errors.New("internal error: TPM object is nil")
	}

	if sel == ar.AK {
		if ak == nil {
			return nil, nil, fmt.Errorf("failed to get AK: not initialized")
		}
		return ak.Private(), ak.Public(), nil
	} else if sel == ar.IK {
		if ik == nil {
			return nil, nil, fmt.Errorf("failed to get IK: not initialized")
		}
		priv, err := ik.Private(ik.Public())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get IK Private")
		}
		return priv, ik.Public(), nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// GetCertChain returns the certificate chain for the specified key
func (t *Tpm) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	if t == nil {
		return nil, errors.New("internal error: TPM object is nil")
	}

	if sel == ar.AK {
		log.Debugf("Returning %v AK certificates", len(t.akChain))
		return t.akChain, nil
	} else if sel == ar.IK {
		log.Debugf("Returning %v IK certificates", len(t.ikChain))
		return t.ikChain, nil
	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// IsTpmProvisioningRequired checks if the Storage Root Key (SRK) is persisted
// at 0x810000001 and the encrypted AK blob is present, which is used as an
// indicator that the TPM is provisioned and the AK can directly be loaded.
// This function uses the low-level go-tpm library directly as go-attestation
// does not provide such a functionality.
func IsTpmProvisioningRequired(storagePath string) (bool, error) {

	// Stateless operation always requires provisioning
	if storagePath == "" {
		log.Info("TPM Credential Activation REQUIRED (no storage path)")
		return true, nil
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(storagePath, akchainFile)); err != nil {
		log.Info("TPM Credential Activation REQUIRED (no AK cert chain)")
		return true, nil
	}
	if _, err := os.Stat(path.Join(storagePath, ikchainFile)); err != nil {
		log.Info("TPM Credential Activation REQUIRED (no IK cert chain)")
		return true, nil
	}
	if _, err := os.Stat(path.Join(storagePath, akFile)); err != nil {
		log.Info("TPM Credential Activation REQUIRED (no AK)")
		return true, nil
	}
	if _, err := os.Stat(path.Join(storagePath, ikFile)); err != nil {
		log.Info("TPM Credential Activation REQUIRED (no IK)")
		return true, nil
	}

	// If the AK is not persisted in the TPM, we need to provision
	addr, err := GetTpmDevicePath()
	if err != nil {
		return true, fmt.Errorf("failed to find TPM device: %w", err)
	}
	rwc, err := tpm2.OpenTPM(addr)
	if err != nil {
		return true, fmt.Errorf("failed to open TPM%v: %w", addr, err)
	}
	defer rwc.Close()
	srkHandle := tpmutil.Handle(0x81000001)
	_, _, _, err = tpm2.ReadPublic(rwc, srkHandle)
	if err == nil {
		log.Info("TPM Provisioning (Credential Activation) NOT REQUIRED")
		return false, nil
	}
	log.Info("TPM Provisioning (Credential Activation) REQUIRED")

	return true, nil
}

func GetTpmDevicePath() (string, error) {
	if _, err := os.Stat(tpmResourceManagerPath); err == nil {
		return tpmResourceManagerPath, nil
	} else if _, err := os.Stat(tpmDevicePath); err == nil {
		return tpmDevicePath, nil
	} else {
		return "", errors.New("failed to find TPM device in /dev")
	}
}

// OpenTpm opens the TPM and stores the handle internally
func OpenTpm() error {
	log.Debug("Opening TPM")

	if TPM != nil {
		return fmt.Errorf("failed to open TPM - already open")
	}

	var err error
	config := &attest.OpenConfig{}
	TPM, err = attest.OpenTPM(config)
	if err != nil {
		TPM = nil
		return fmt.Errorf("activate credential failed: OpenTPM returned %w", err)
	}

	return nil
}

// CloseTpm closes the TPM
func CloseTpm() error {
	if TPM == nil {
		return fmt.Errorf("failed to close TPM - TPM is not openend")
	}
	TPM.Close()
	TPM = nil
	return nil
}

// GetTpmInfo retrieves general TPM infos
func GetTpmInfo() (*attest.TPMInfo, error) {

	if TPM == nil {
		return nil, fmt.Errorf("failed to Get TPM info - TPM is not openend")
	}

	tpmInfo, err := TPM.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM info - %w", err)
	}

	log.Debug("Version             : ", tpmInfo.Version)
	log.Debug("FirmwareVersionMajor: ", tpmInfo.FirmwareVersionMajor)
	log.Debug("FirmwareVersionMinor: ", tpmInfo.FirmwareVersionMinor)
	log.Debug("Interface           : ", tpmInfo.Interface)
	log.Debug("Manufacturer        : ", tpmInfo.Manufacturer.String())

	return tpmInfo, nil
}

// GetAkQualifiedName gets the Attestation Key Qualified Name. According to
// Trusted Platform Module Library Part 1: Architecture:
//
//	Name = nameAlg || HASH (TPMS_NV_PUBLIC)
//	QName = HASH(QName_parent || Name)
func GetAkQualifiedName() ([]byte, error) {

	if TPM == nil {
		return nil, errors.New("failed to get AK Qualified Name: TPM is not opened")
	}
	if ak == nil {
		return nil, errors.New("failed to get AK Qualified Name: AK does not exist")
	}

	// This is a TPMT_PUBLIC structure
	pub := ak.AttestationParameters().Public

	// TPMT_PUBLIC Contains algorithm used for hashing the public area to get
	// the name (nameAlg)
	tpm2Pub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to Decode AK Public: %w", err)
	}

	if tpm2Pub.NameAlg != tpm2.AlgSHA256 {
		return nil, errors.New("failed to Get AK public: unsupported hash algorithm")
	}

	// Name of object is nameAlg || Digest(TPMT_PUBLIC)
	alg := make([]byte, 2)
	binary.BigEndian.PutUint16(alg, uint16(tpm2Pub.NameAlg))
	digestPub := sha256.Sum256(pub)
	name := append(alg, digestPub[:]...)

	// TPMS_CREATION_DATA contains parentQualifiedName
	createData := ak.AttestationParameters().CreateData
	tpm2CreateData, err := tpm2.DecodeCreationData(createData)
	if err != nil {
		return nil, fmt.Errorf("failed to Decode Creation Data: %w", err)
	}

	parentAlg := make([]byte, 2)
	binary.BigEndian.PutUint16(parentAlg, uint16(tpm2CreateData.ParentNameAlg))
	parentQualifiedName := append(parentAlg, tpm2CreateData.ParentQualifiedName.Digest.Value...)

	// QN_AK := H_AK(QN_Parent || NAME_AK)
	buf := append(parentQualifiedName[:], name[:]...)
	qualifiedNameDigest := sha256.Sum256(buf)
	qualifiedName := append(alg, qualifiedNameDigest[:]...)

	log.Debugf("AK Name: %v", hex.EncodeToString(name[:]))
	log.Debugf("AK Qualified Name: %v", hex.EncodeToString(qualifiedName[:]))

	return qualifiedName, nil
}

// GetMeasurement retrieves the specified PCRs as well as a Quote over the PCRs
// and returns the TPM quote as well as the single PCR values
func (t *Tpm) GetMeasurement(nonce []byte) ([]attest.PCR, *attest.Quote, error) {

	if TPM == nil {
		return nil, nil, fmt.Errorf("TPM is not opened")
	}
	if ak == nil {
		return nil, nil, fmt.Errorf("AK does not exist")
	}

	// Read and Store PCRs into TPM Measurement structure. Lock this access, as only
	// one instance can have write access at the same time
	t.Lock()
	defer t.Unlock()

	pcrValues, err := TPM.PCRs(attest.HashSHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TPM PCRs: %w", err)
	}
	log.Debug("Finished reading PCRs from TPM")

	// Retrieve quote and store quote data and signature in TPM measurement object
	quote, err := ak.QuotePCRs(TPM, nonce, attest.HashSHA256, t.pcrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TPM quote - %w", err)
	}
	log.Debug("Finished getting Quote from TPM")

	return pcrValues, quote, nil
}

func GetEventLogs(serializer ar.Serializer,
	biosLog, imaLog, ctrLog bool,
	pcrs []int, imaPcr, ctrPcr int,
	ctrLogFile string, pcrValues map[int][]byte,
) ([]ar.Artifact, error) {

	// If configured, try to read the kernel binary bios measurements
	// and use these values, which represent the software artifacts that have been
	// extended. Use the final PCR values as a fallback, if the file cannot be read
	var biosMeasurements []ar.ReferenceValue
	var err error
	if biosLog {
		log.Debug("Collecting binary bios measurements")
		biosMeasurements, err = GetBiosMeasurements(DEFAULT_BINARY_BIOS_MEASUREMENTS, DEFAULT_EVENT_TYPE, false)
		if err != nil {
			log.Warnf("failed to read binary bios measurements: %v. Using final PCR values as measurements",
				err)
		}
		log.Debugf("Collected %v binary bios measurements", len(biosMeasurements))
	}

	artifacts := make([]ar.Artifact, len(pcrs))
	for i, num := range pcrs {

		events := make([]ar.MeasureEvent, 0)

		pcrMeasurement := ar.Artifact{
			Index: num,
		}

		// Collect detailed measurements from event logs if specified
		if biosLog {
			for _, digest := range biosMeasurements {
				if num == digest.Index {
					event := ar.MeasureEvent{
						Sha256:    digest.Sha256,
						EventName: digest.SubType,
					}
					if digest.SubType != "TPM_PCR_INIT_VALUE" {
						event.EventData = digest.EventData
					}
					events = append(events, event)
				}
			}
			pcrMeasurement.Type = "PCR Eventlog"
			pcrMeasurement.Events = events
		} else {
			pcrValue, ok := pcrValues[num]
			if !ok {
				return nil, fmt.Errorf("failed to get PCR value %v", num)
			}
			pcrMeasurement.Type = "PCR Summary"
			pcrMeasurement.Events = append(pcrMeasurement.Events, ar.MeasureEvent{
				Sha256: pcrValue,
			})
		}

		artifacts[i] = pcrMeasurement
	}

	if imaLog {
		// If the IMA is used, not the final PCR value is sent but instead
		// a list of the kernel modules which are extended during verification
		// to result in the final value
		imaEvents, err := ima.GetImaRuntimeDigests(ima.DEFAULT_BINARY_RUNTIME_MEASUREMENTS)
		if err != nil {
			return nil, fmt.Errorf("failed to get IMA runtime digests: %v", err)
		}

		// Find the IMA PCR in the TPM Measurement
		for i := range artifacts {
			if artifacts[i].Index == imaPcr {
				log.Debugf("Adding %v IMA events to PCR%v measurement", len(imaEvents), artifacts[i].Index)
				artifacts[i].Events = imaEvents
				artifacts[i].Type = "PCR Eventlog"
			}
		}
	}

	if ctrLog {
		log.Debugf("Reading container measurements")
		if _, err := os.Stat(ctrLogFile); err == nil {
			// If CMC container measurements are used, add the list of executed containers
			data, err := os.ReadFile(ctrLogFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read container measurements: %w", err)
			}

			var measureList []ar.MeasureEvent
			err = serializer.Unmarshal(data, &measureList)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal measurement list: %w", err)
			}

			for i := range artifacts {
				if artifacts[i].Index == ctrPcr {
					log.Debugf("Adding %v container events to PCR%v measurement", len(measureList),
						artifacts[i].Index)
					artifacts[i].Type = "PCR Eventlog"
					artifacts[i].Events = measureList
				}
			}
		} else {
			log.Trace("No container measurements to read")
		}
	} else {
		log.Trace("TPM PCR Container measurements omitted: not configured")
	}

	return artifacts, nil
}

func (t *Tpm) provision(c *ar.DriverConfig) error {
	var err error

	log.Debug("Performing TPM credential activation..")

	if TPM == nil {
		return errors.New("TPM is not openend")
	}

	ek, ak, ik, err = createKeys(TPM, c.KeyConfig)
	if err != nil {
		return fmt.Errorf("activate credential failed: createKeys returned %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := c.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	akCert, err := t.provisionAk(c)
	if err != nil {
		return fmt.Errorf("failed to provision AK cert chain: %w", err)
	}
	t.akChain = append([]*x509.Certificate{akCert}, caCerts...)

	ikCert, err := t.provisionIk(c)
	if err != nil {
		return fmt.Errorf("failed to provision IK cert chain: %w", err)
	}
	t.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	return nil
}

func (t *Tpm) provisionAk(c *ar.DriverConfig) (*x509.Certificate, error) {

	log.Debug("Provisioning AK certificate..")

	// Retrieve TPM information
	tpmInfo, err := GetTpmInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TPM Info: %w", err)
	}

	// Encode EK public key
	ekPub, err := x509.MarshalPKIXPublicKey(ek[0].Public)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EK public key: %w", err)
	}
	var ekRaw []byte
	if ek[0].Certificate != nil {
		log.Debugf("Using EK %v", ek[0].Certificate.Subject.CommonName)
		ekRaw = ek[0].Certificate.Raw
	} else if ek[0].CertificateURL != "" {
		log.Debugf("Using EK URL %q", ek[0].CertificateURL)
		ekRaw = nil
	}

	// Create AK CSR and perform EST enrollment with TPM credential activation
	akCsr, err := createAkCsr(ak, c.DeviceConfig.Tpm.AkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create AK CSR: %w", err)
	}

	log.Debugf("Performing AK TPM activate credential enroll for CN=%v", akCsr.Subject.CommonName)
	encCredential, encSecret, pkcs7Cert, err := c.Provisioner.TpmActivateEnroll(
		tpmInfo.Manufacturer.String(), ek[0].CertificateURL,
		tpmInfo.FirmwareVersionMajor, tpmInfo.FirmwareVersionMinor,
		akCsr,
		ak.AttestationParameters(),
		ekPub, ekRaw,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll AK: %w", err)
	}

	log.Debugf("Performing credential activation")
	secret, err := ActivateCredential(TPM, ak, encCredential, encSecret)
	if err != nil {
		return nil, fmt.Errorf("request activate credential failed: %w", err)
	}

	encryptedCert, err := pkcs7.Parse(pkcs7Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7 CMS EnvelopedData: %w", err)
	}

	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	certDer, err := encryptedCert.DecryptUsingPSK(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PKCS7 encrypted cert: %w", err)
	}

	akCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Debugf("Provisioned new AK Cert: %v", akCert.Subject.CommonName)

	return akCert, nil
}

func (t *Tpm) provisionIk(c *ar.DriverConfig) (*x509.Certificate, error) {

	log.Debug("Provisioning IK certificate..")

	// Create IK CSR and perform EST enrollment with TPM certification
	ikPriv, err := ik.Private(ik.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve IK private key: %w", err)
	}

	ikCsr, err := ar.CreateCsr(ikPriv, c.DeviceConfig.Tpm.IkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK CSR: %w", err)
	}

	ikParams := ik.CertificationParameters()

	// Use Subject Key Identifier (SKI) as nonce for attestation report
	pubKey, err := x509.MarshalPKIXPublicKey(ikCsr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR public key: %v", err)
	}
	nonce := sha1.Sum(pubKey)

	// Fetch attestation report as part of client authentication if configured
	var report []byte
	var metadata [][]byte
	if c.ProvisionAuth.Has(internal.AuthAttestation) {
		r, m, err := prover.Generate(nonce[:], nil, c.Metadata, []ar.Driver{t}, c.Serializer)
		if err != nil {
			return nil, fmt.Errorf("failed to generate attestation report: %w", err)
		}
		metadata = internal.ConvertToArray(m)
		data, err := c.Serializer.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
		}
		report, err = prover.Sign(data, t, c.Serializer, ar.IK)
		if err != nil {
			return nil, fmt.Errorf("failed to sign attestation report: %w", err)
		}
	}

	log.Debugf("Performing IK TPM certify enroll for CN=%v", ikCsr.Subject.CommonName)
	ikCert, err := c.Provisioner.TpmCertifyEnroll(
		ikCsr,
		ikParams,
		ak.AttestationParameters().Public,
		report,
		metadata,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK: %w", err)
	}

	log.Debugf("Created new IK cert: %v", ikCert.Subject.CommonName)

	return ikCert, nil
}

func (t *Tpm) saveCredentials(storagePath string) error {

	// Store the encrypted AK blob on disk
	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal AK returned %w", err)
	}
	akPath := path.Join(storagePath, akFile)
	if err := os.WriteFile(akPath, akBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file %v: %w", akPath, err)
	}

	// Store the encrypted IK blob on disk
	ikBytes, err := ik.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal IK returned %w", err)
	}
	ikPath := path.Join(storagePath, ikFile)
	if err := os.WriteFile(ikPath, ikBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file %v: %w", ikPath, err)
	}

	// Store the AK chain on disk
	akchainPem := make([]byte, 0)
	for _, cert := range t.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(storagePath, akchainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(storagePath, akchainFile), err)
	}

	// Store the IK chain on disk
	ikchainPem := make([]byte, 0)
	for _, cert := range t.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(storagePath, ikchainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(storagePath, ikchainFile), err)
	}

	return nil
}

func (t *Tpm) loadCredentials(storagePath string) error {

	if TPM == nil {
		return errors.New("tpm is not opened")
	}

	// Load encrypted AK into TPM
	akPath := path.Join(storagePath, akFile)
	akBytes, err := os.ReadFile(akPath)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %w", akPath, err)
	}
	ak, err = TPM.LoadAK(akBytes)
	if err != nil {
		return fmt.Errorf("LoadAK failed: %w", err)
	}
	log.Debug("Loaded AK")

	// Load encrypted IK into TPM
	ikPath := path.Join(storagePath, ikFile)
	ikBytes, err := os.ReadFile(ikPath)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %w", ikPath, err)
	}
	ik, err = TPM.LoadKey(ikBytes)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}
	log.Debug("Loaded IK")

	// Load AK chain
	data, err := os.ReadFile(path.Join(storagePath, akchainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", storagePath, err)
	}
	t.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(t.akChain))

	// Load IK chain
	data, err = os.ReadFile(path.Join(storagePath, ikchainFile))
	if err != nil {
		return fmt.Errorf("failed to read IK chain from %v: %w", storagePath, err)
	}
	t.ikChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(t.ikChain))

	return nil
}

func createKeys(tpm *attest.TPM, keyConfig string) ([]attest.EK, *attest.AK, *attest.Key, error) {

	log.Debug("Loading EKs")

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load EKs - %w", err)
	}
	log.Debugf("Found %v EK(s)", len(eks))

	log.Debug("Creating new AK")
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create new AK - %w", err)
	}

	log.Debug("Creating new IK")

	// Create key as specified in the config file
	ikConfig := &attest.KeyConfig{}
	switch keyConfig {
	case "EC256":
		ikConfig.Algorithm = attest.ECDSA
		ikConfig.Size = 256
	case "EC384":
		ikConfig.Algorithm = attest.ECDSA
		ikConfig.Size = 384
	case "EC521":
		ikConfig.Algorithm = attest.ECDSA
		ikConfig.Size = 521
	case "RSA2048":
		ikConfig.Algorithm = attest.RSA
		ikConfig.Size = 2048
	case "RSA4096":
		ikConfig.Algorithm = attest.RSA
		ikConfig.Size = 4096
	default:
		return nil, nil, nil, fmt.Errorf(
			"failed to create new IK Key, unknown key configuration: %v", keyConfig)
	}

	ik, err := tpm.NewKey(ak, ikConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create new IK key - %w", err)
	}

	return eks, ak, ik, nil
}

func ActivateCredential(
	tpm *attest.TPM, ak *attest.AK,
	activationCredential, activationSecret []byte,
) ([]byte, error) {

	if activationCredential == nil {
		return nil, errors.New("did not receive encrypted credential from server")
	}
	if activationSecret == nil {
		return nil, errors.New("did not receive encrypted secret from server")
	}

	encryptedCredential := attest.EncryptedCredential{
		Credential: activationCredential,
		Secret:     activationSecret,
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredential)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed: %w", err)
	}

	return secret, nil
}

func getQuotePcrs(t *Tpm) ([]int, error) {

	if TPM == nil {
		return nil, fmt.Errorf("TPM is not opened")
	}

	// Read and Store PCRs into TPM Measurement structure. Lock this access, as only
	// one instance can have write access at the same time
	t.Lock()
	defer t.Unlock()

	log.Debug("Retrieving PCRs")
	pcrValues, err := TPM.PCRs(attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM PCRs: %w", err)
	}

	// Assume an SRTM system by default and quote the static PCRs
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}

	// Check if the system is a DRTM system
	for _, pcr := range pcrValues {
		if pcr.Index == 17 {
			cmp := make([]byte, pcr.DigestAlg.Size())
			for i := range cmp {
				cmp[i] = 0xff
			}

			// If PCR17 recorded measurements, this means the system is a DRTM systen,
			// so the dynamic PCRs must be quoted
			if !bytes.Equal(pcr.Digest, cmp) {
				pcrs = []int{17, 18, 19, 20, 21, 22}
			}
		}
	}

	pcrs = internal.FilterInts(pcrs, t.excludedPcrs)

	log.Debugf("Using PCRs: %v", pcrs)

	return pcrs, nil
}

// This function calls the modified version of x509.CreateCertificateRequest which does not
// perform hashing and can therefore be used to create CSRs for restricted tpm keys
func createAkCsr(ak *attest.AK, params ar.CsrParams) (*x509.CertificateRequest, error) {

	log.Debugf("Creating AK CSR..")

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         params.Subject.CommonName,
			Country:            []string{params.Subject.Country},
			Province:           []string{params.Subject.Province},
			Locality:           []string{params.Subject.Locality},
			Organization:       []string{params.Subject.Organization},
			OrganizationalUnit: []string{params.Subject.OrganizationalUnit},
			StreetAddress:      []string{params.Subject.StreetAddress},
			PostalCode:         []string{params.Subject.PostalCode},
		},
	}

	// NOTE does not call x509.CreateCertificateRequest but instead a local
	// modified version
	der, err := CreateCertificateRequest(rand.Reader, &tmpl, ak.Private())
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %w", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %w", err)
	}

	return csr, nil
}
