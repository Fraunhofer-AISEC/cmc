// Copyright (c) 2021 Fraunhofer AISEC
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
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"sync"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	"go.mozilla.org/pkcs7"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/ima"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// Tpm is a structure that implements the Measure method
// of the attestation report Measurer interface
type Tpm struct {
	Mu             sync.Mutex
	Pcrs           []int
	SigningCerts   []*x509.Certificate
	MeasuringCerts []*x509.Certificate
	UseIma         bool
	ImaPcr         int32
	MeasurementLog bool
}

const (
	akchainFile = "akchain.pem"
	ikchainFile = "ikchain.pem"
	akFile      = "ak_encrypted.json"
	ikFile      = "ik_encrypted.json"
)

var (
	TPM *attest.TPM = nil
	ak  *attest.AK  = nil
	ik  *attest.Key = nil
	ek  []attest.EK
)

var log = logrus.WithField("service", "tpmdriver")

// Init opens and initializes a TPM object, checks if provosioning is
// required and if so, provisions the TPM
func (t *Tpm) Init(c *ar.DriverConfig) error {

	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}

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

	// Retrieve the TPM PCRs to be included in the attestation report from
	// the manifest files
	pcrs, err := getTpmPcrs(c)
	if err != nil {
		return fmt.Errorf("failed to retrieve TPM PCRs: %w", err)
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

	var akchain []*x509.Certificate
	var ikchain []*x509.Certificate
	if provisioningRequired {

		log.Info("Provisioning TPM (might take a while)..")
		ek, ak, ik, err = createKeys(TPM, c.KeyConfig)
		if err != nil {
			return fmt.Errorf("activate credential failed: createKeys returned %w", err)
		}

		// Load relevant parameters from the metadata files
		akCsr, ikCsr, err := createCsrs(c, ak, ik)
		if err != nil {
			return fmt.Errorf("failed to create CSRs: %w", err)
		}

		log.Tracef("Created AK CSR: %v", akCsr.Subject.CommonName)
		log.Tracef("Created IK CSR: %v", ikCsr.Subject.CommonName)

		akchain, ikchain, err = provisionTpm(c.ServerAddr, akCsr, ikCsr)
		if err != nil {
			return fmt.Errorf("failed to provision TPM: %w", err)
		}

		if c.StoragePath != "" {
			err = saveCerts(c.StoragePath, akchain, ikchain)
			if err != nil {
				return fmt.Errorf("failed to save TPM data: %w", err)
			}

			err = saveKeys(c.StoragePath)
			if err != nil {
				return fmt.Errorf("failed to save keys: %w", err)
			}
		}

	} else {
		err = loadTpmKeys(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load TPM keys: %w", err)
		}
		akchain, ikchain, err = loadTpmCerts(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load TPM certificates: %w", err)
		}
	}

	name, err := GetAkQualifiedName()
	if err != nil {
		return fmt.Errorf("failed to get AK qualified name: %w", err)
	}
	log.Debugf("Using AK with qualified name: %v", hex.EncodeToString(name))

	t.Pcrs = pcrs
	t.UseIma = c.UseIma
	t.ImaPcr = c.ImaPcr
	t.SigningCerts = ikchain
	t.MeasuringCerts = akchain
	t.MeasurementLog = c.MeasurementLog

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (t *Tpm) Measure(nonce []byte) (ar.Measurement, error) {

	if t == nil {
		return ar.TpmMeasurement{}, fmt.Errorf("internal error: tpm object not initialized")
	}
	if len(t.Pcrs) == 0 {
		log.Warn("TPM measurement based on reference values does not contain any PCRs")
	}

	log.Trace("Collecting TPM Quote")

	pcrValues, quote, err := GetTpmMeasurement(t, nonce, t.Pcrs)
	if err != nil {
		return ar.TpmMeasurement{}, fmt.Errorf("failed to get TPM Measurement: %w", err)
	}

	// For a more detailed measurement, try to read the kernel binary bios measurements
	// and use these values, which represent the software artifacts that have been
	// extended. Use the final PCR values only as a fallback, if the file cannot be read
	var biosMeasurements []ar.ReferenceValue
	if t.MeasurementLog {
		log.Trace("Collecting binary bios measurements")
		biosMeasurements, err = GetBiosMeasurements("/sys/kernel/security/tpm0/binary_bios_measurements")
		if err != nil {
			t.MeasurementLog = false
			log.Warnf("failed to read binary bios measurements: %v. Using final PCR values as measurements",
				err)
		}
	}

	hashChain := make([]*ar.HashChainElem, len(t.Pcrs))
	for i, num := range t.Pcrs {
		sha256 := make([]ar.HexByte, 0)
		eventNameArray := make([]string, 0)
		eventDataArray := make([]ar.EventData, 0)

		if t.MeasurementLog {
			for _, digest := range biosMeasurements {
				if num == *digest.Pcr {
					sha256 = append(sha256, digest.Sha256)
					eventNameArray = append(eventNameArray, digest.Name)

					if digest.Name == "TPM_PCR_INIT_VALUE" {
						eventDataArray = append(eventDataArray, ar.EventData{})
					} else {
						eventDataArray = append(eventDataArray, *digest.EventData)
					}
				}
			}
		} else {
			sha256 = append(sha256, pcrValues[num].Digest)
		}

		hashChain[i] = &ar.HashChainElem{
			Type:    "Hash Chain",
			Pcr:     int32(num),
			Sha256:  sha256,
			Summary: !t.MeasurementLog,
		}
		//appending EventData
		if t.MeasurementLog {
			hashChain[i].EventData = eventDataArray
			hashChain[i].EventName = eventNameArray
		}
	}

	if t.UseIma {
		// If the IMA is used, not the final PCR value is sent but instead
		// a list of the kernel modules which are extended during verification
		// to result in the final value
		imaDigests, err := ima.GetImaRuntimeDigests()
		if err != nil {
			log.Error("failed to get IMA runtime digests. Ignoring..")
		}

		imaDigestsHex := make([]ar.HexByte, 0)
		for _, elem := range imaDigests {
			imaDigestsHex = append(imaDigestsHex, elem[:])
		}

		// Find the IMA PCR in the TPM Measurement
		for _, elem := range hashChain {
			if elem.Pcr == t.ImaPcr {
				elem.Sha256 = imaDigestsHex
				elem.Summary = false
			}
		}
	}

	tm := ar.TpmMeasurement{
		Type:      "TPM Measurement",
		HashChain: hashChain,
		Message:   quote.Quote,
		Signature: quote.Signature,
		Certs:     internal.WriteCertsDer(t.MeasuringCerts),
	}

	for _, elem := range tm.HashChain {
		for _, sha := range elem.Sha256 {
			log.Tracef("PCR%v: %v\n", elem.Pcr, hex.EncodeToString(sha))
		}
	}
	log.Trace("Quote: ", hex.EncodeToString(tm.Message))
	log.Trace("Signature: ", hex.EncodeToString(tm.Signature))

	return tm, nil
}

func (t *Tpm) Lock() error {
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	log.Trace("Trying to get lock for TPM")
	t.Mu.Lock()
	log.Trace("Got lock for TPM")
	return nil
}

func (t *Tpm) Unlock() error {
	if t == nil {
		return errors.New("internal error: TPM object is nil")
	}
	log.Trace("Releasing TPM Lock")
	t.Mu.Unlock()
	log.Trace("Released TPM Lock")
	return nil
}

// GetSigningKeys returns the IK private and public key as a generic
// crypto interface
func (t *Tpm) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {

	if t == nil {
		return nil, nil, errors.New("internal error: TPM object is nil")
	}
	if ik == nil {
		return nil, nil, fmt.Errorf("failed to get IK Signer: not initialized")
	}
	priv, err := ik.Private(ik.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get IK Private")
	}

	return priv, ik.Public(), nil
}

func (t *Tpm) GetCertChain() ([]*x509.Certificate, error) {
	if t == nil {
		return nil, errors.New("internal error: TPM object is nil")
	}
	log.Tracef("Returning %v certificates", len(t.SigningCerts))
	return t.SigningCerts, nil
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
	addr, err := getTpmAddr()
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

func getTpmAddr() (string, error) {
	// TODO more robust
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return "/dev/tpmrm0", nil
	} else if _, err := os.Stat("/dev/tpm0"); err == nil {
		return "/dev/tpm0", nil
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

// GetTpmMeasurement retrieves the specified PCRs as well as a Quote over the PCRs
// and returns the TPM quote as well as the single PCR values
func GetTpmMeasurement(t *Tpm, nonce []byte, pcrs []int) ([]attest.PCR, *attest.Quote, error) {

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
	log.Trace("Finished reading PCRs from TPM")

	// Retrieve quote and store quote data and signature in TPM measurement object
	quote, err := ak.QuotePCRs(TPM, nonce, attest.HashSHA256, pcrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TPM quote - %w", err)
	}
	log.Trace("Finished getting Quote from TPM")

	return pcrValues, quote, nil
}

func provisionTpm(
	provServerURL string, akCsr, ikCsr *x509.CertificateRequest,
) ([]*x509.Certificate, []*x509.Certificate, error) {
	log.Debug("Performing TPM credential activation..")

	if TPM == nil {
		return nil, nil, errors.New("TPM is not openend")
	}
	if len(ek) == 0 || ak == nil || ik == nil {
		return nil, nil, errors.New("keys not created")
	}

	tpmInfo, err := GetTpmInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve TPM Info: %w", err)
	}

	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	log.Info("Retrieving CA certs")
	caCerts, err := client.CaCerts(provServerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve certificates: %w", err)
	}
	log.Debugf("Received cert chain length %v:", len(caCerts))
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}

	log.Warn("Setting retrieved certificate for future authentication")
	err = client.SetCAs([]*x509.Certificate{caCerts[len(caCerts)-1]})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set EST CA: %w", err)
	}

	akParams := ak.AttestationParameters()

	// Encode EK public key
	ekPub, err := x509.MarshalPKIXPublicKey(ek[0].Public)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal EK public key: %w", err)
	}

	var ekRaw []byte
	if ek[0].Certificate != nil {
		ekRaw = ek[0].Certificate.Raw
	} else {
		ekRaw = nil
		log.Tracef("EK not present. Using EK URL %v", ek[0].CertificateURL)
	}

	log.Info("Performing TPM AK Enroll")
	encCredential, encSecret, pkcs7Cert, err := client.TpmActivateEnroll(
		provServerURL, tpmInfo.Manufacturer.String(), ek[0].CertificateURL,
		tpmInfo.FirmwareVersionMajor, tpmInfo.FirmwareVersionMinor,
		akCsr,
		akParams.Public, akParams.CreateData, akParams.CreateAttestation, akParams.CreateSignature,
		ekPub, ekRaw,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enroll AK: %w", err)
	}

	secret, err := ActivateCredential(TPM, ak, encCredential, encSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("request activate credential failed: %w", err)
	}

	encryptedCert, err := pkcs7.Parse(pkcs7Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PKCS7 CMS EnvelopedData: %w", err)
	}

	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	certDer, err := encryptedCert.DecryptUsingPSK(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt PKCS7 encrypted cert: %w", err)
	}

	akCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Tracef("Created new AK Cert: %v", akCert.Subject.CommonName)

	log.Info("Performing TPM IK Enroll")
	ikParams := ik.CertificationParameters()

	ikCert, err := client.TpmCertifyEnroll(
		provServerURL,
		ikCsr,
		ikParams.Public, ikParams.CreateData, ikParams.CreateAttestation, ikParams.CreateSignature,
		akParams.Public,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enroll IK: %w", err)
	}

	log.Tracef("Created new IK cert: %v", ikCert.Subject.CommonName)

	akchain := append([]*x509.Certificate{akCert}, caCerts...)
	ikchain := append([]*x509.Certificate{ikCert}, caCerts...)

	return akchain, ikchain, nil
}

func saveCerts(storagePath string, akchain, ikchain []*x509.Certificate) error {

	akchainPem := make([]byte, 0)
	for _, cert := range akchain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(storagePath, akchainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(storagePath, akchainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range ikchain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(storagePath, ikchainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(storagePath, ikchainFile), err)
	}

	return nil
}

func saveKeys(storagePath string) error {
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

	return nil
}

func loadTpmKeys(storagePath string) error {

	if TPM == nil {
		return errors.New("tpm is not opened")
	}

	log.Debug("Loading TPM keys..")

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

	return nil
}

func loadTpmCerts(storagePath string) ([]*x509.Certificate, []*x509.Certificate, error) {

	data, err := os.ReadFile(path.Join(storagePath, akchainFile))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read AK chain from %v: %w", storagePath, err)
	}
	akchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Tracef("Parsed stored AK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(storagePath, ikchainFile))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read IK chain from %v: %w", storagePath, err)
	}
	ikchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Tracef("Parsed stored IK chain of length %v", len(akchain))

	return akchain, ikchain, nil
}

func createKeys(tpm *attest.TPM, keyConfig string) ([]attest.EK, *attest.AK, *attest.Key, error) {

	log.Debug("Loading EKs")

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load EKs - %w", err)
	}
	log.Tracef("Found %v EK(s)", len(eks))

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

func getTpmPcrs(c *ar.DriverConfig) ([]int, error) {

	var osMan ar.OsManifest
	var rtmMan ar.RtmManifest

	for i, m := range c.Metadata {

		// Extract plain payload (i.e. the manifest/description itself)
		payload, err := c.Serializer.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata to determine the type
		info := new(ar.MetaInfo)
		err = c.Serializer.Unmarshal(payload, info)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if info.Type == "RTM Manifest" {
			err = c.Serializer.Unmarshal(payload, &rtmMan)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal data from RTM Manifest: %w", err)
			}
		} else if info.Type == "OS Manifest" {
			err = c.Serializer.Unmarshal(payload, &osMan)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal data from OS Manifest: %w", err)
			}
		}
	}

	// Check if manifests were found
	if osMan.Type != "OS Manifest" || rtmMan.Type != "RTM Manifest" {
		return nil, errors.New("failed to find all manifests")
	}

	// Generate the list of PCRs to be included in the quote
	pcrs := make([]int, 0)
	log.Debugf("Parsing %v RTM Reference Values", len(rtmMan.ReferenceValues))
	for _, ver := range rtmMan.ReferenceValues {
		if ver.Type != "TPM Reference Value" || ver.Pcr == nil {
			continue
		}
		if !exists(*ver.Pcr, pcrs) {
			pcrs = append(pcrs, *ver.Pcr)
		}
	}
	log.Debugf("Parsing %v OS Reference Values", len(osMan.ReferenceValues))
	for _, ver := range osMan.ReferenceValues {
		if ver.Type != "TPM Reference Value" || ver.Pcr == nil {
			continue
		}
		if !exists(*ver.Pcr, pcrs) {
			pcrs = append(pcrs, *ver.Pcr)
		}
	}

	sort.Ints(pcrs)

	return pcrs, nil
}

func createCsrs(c *ar.DriverConfig, ak *attest.AK, ik *attest.Key,
) (akCsr, ikCsr *x509.CertificateRequest, err error) {

	// Get device configuration from metadata
	for i, m := range c.Metadata {

		// Extract plain payload of metadata
		payload, err := c.Serializer.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata file to determine the type
		info := new(ar.MetaInfo)
		err = c.Serializer.Unmarshal(payload, info)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if info.Type == "Device Config" {
			log.Tracef("Found Device Config")
			var deviceConfig ar.DeviceConfig
			err = c.Serializer.Unmarshal(payload, &deviceConfig)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to unmarshal DeviceConfig: %w", err)
			}
			akCsr, err = createAkCsr(ak, deviceConfig.AkCsr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create AK CSR: %w", err)
			}
			ikCsr, err = createIkCsr(ik, deviceConfig.IkCsr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create IK CSR: %w", err)
			}
			return akCsr, ikCsr, nil
		}
	}

	return nil, nil, errors.New("failed to find device configuration")
}

func createAkCsr(ak *attest.AK, params ar.CsrParams) (*x509.CertificateRequest, error) {

	log.Tracef("Creating AK CSR..")

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

func createIkCsr(ik *attest.Key, params ar.CsrParams) (*x509.CertificateRequest, error) {

	log.Tracef("Creating IK CSR..")

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
		DNSNames: params.SANs,
	}

	priv, err := ik.Private(ik.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve IK private key: %w", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
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

func exists(i int, arr []int) bool {
	for _, elem := range arr {
		if elem == i {
			return true
		}
	}
	return false
}
