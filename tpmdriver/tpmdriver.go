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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"sync"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/ima"
)

var (
	tpmProtocolVersion = 2
)

// Tpm is a structure that implements the Measure method
// of the attestation report Measurer interface
type Tpm struct {
	Mu             sync.Mutex
	Pcrs           []int
	SigningCerts   ar.CertChain
	MeasuringCerts ar.CertChain
	UseIma         bool
	ImaPcr         int32
}

// Config is the structure for handing over the configuration
// for a Tpm object
type Config struct {
	StoragePath string
	ServerAddr  string
	KeyConfig   string
	Metadata    [][]byte
	UseIma      bool
	ImaPcr      int32
	Serializer  ar.Serializer
}

// AcRequest holds the data for an activate credential request
// for verifying that the AK and IK were created on a genuine
// TPM with a valid EK
type AcRequest struct {
	Version         int
	AkQualifiedName [32]byte
	TpmInfo         attest.TPMInfo
	Ek              attest.EK
	AkParams        attest.AttestationParameters
	IkParams        attest.CertificationParameters
}

// AcResponse holds the activate credential challenge
type AcResponse struct {
	Version         int
	AkQualifiedName [32]byte
	Ec              attest.EncryptedCredential
}

// AkCertRequest holds the secret from the activate
// credential challenge as well as certificate parameters
// of the to be generated certificates (as the AK can only sign
// objects form within the TPM, a CSR is not possible)
type AkCertRequest struct {
	Version         int
	AkQualifiedName [32]byte
	Secret          []byte
	AkCsr           []byte
	IkCsr           []byte
}

// AkCertResponse holds the issued certificates including the
// certificate chain up to a Root CA
type AkCertResponse struct {
	Version         int
	AkQualifiedName [32]byte
	AkCertChain     ar.CertChain
	IkCertChain     ar.CertChain
}

// Paths specifies the paths to store the encrypted TPM key blobs
// and the certificates
type Paths struct {
	Ak            string
	Ik            string
	AkCert        string
	IkCert        string
	Intermediates []string
	Ca            string
}

var (
	TPM *attest.TPM = nil
	ak  *attest.AK  = nil
	ik  *attest.Key = nil
	ek  []attest.EK
)

var log = logrus.WithField("service", "tpmdriver")

// NewTpm creates a new TPM object, opens and initializes the TPM object,
// checks if provosioning is required and if so, provisions the TPM
func NewTpm(c *Config) (*Tpm, error) {

	// Check if serializer is initialized
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return nil, fmt.Errorf("serializer not initialized in driver config")
	}

	paths, err := createLocalStorage(c.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create local storage: %v", err)
	}

	// Retrieve the TPM PCRs to be included in the attestation report from
	// the manifest files
	pcrs, err := getTpmPcrs(c)
	if err != nil {
		return nil, fmt.Errorf("failed retrieve TPM PCRs: %v", err)
	}

	// Check if the TPM is provisioned. If provisioned, load the AK and IK key.
	// Otherwise perform credential activation with provisioning server and then load the keys
	provisioningRequired, err := IsTpmProvisioningRequired(paths)
	if err != nil {
		return nil, fmt.Errorf("failed to check if TPM is provisioned: %v", err)
	}

	err = OpenTpm()
	if err != nil {
		return nil, fmt.Errorf("failed to open the TPM. Check if you have privileges to open /dev/tpm0: %v", err)
	}

	var akchain ar.CertChain
	var ikchain ar.CertChain
	if provisioningRequired {

		log.Info("Provisioning TPM (might take a while)..")
		ek, ak, ik, err = createKeys(TPM, c.KeyConfig)
		if err != nil {
			return nil, fmt.Errorf("activate credential failed: createKeys returned %v", err)
		}

		// Load relevant parameters from the metadata files
		akCsr, ikCsr, err := createCsrs(c, ak, ik)
		if err != nil {
			return nil, fmt.Errorf("failed to create CSRs: %v", err)
		}

		log.Tracef("Created AK CSR: %v", string(akCsr))
		log.Tracef("Created IK CSR: %v", string(ikCsr))

		akchain, ikchain, err = provisionTpm(c.ServerAddr+"activate-credential/", akCsr, ikCsr)
		if err != nil {
			return nil, fmt.Errorf("failed to provision TPM: %v", err)
		}

		err = saveTpmData(c, paths, &akchain, &ikchain)
		if err != nil {
			os.Remove(paths.Ak)
			os.Remove(paths.Ik)
			return nil, fmt.Errorf("failed to save TPM data: %v", err)
		}

	} else {
		err = loadTpmKeys(paths.Ak, paths.Ik)
		if err != nil {
			return nil, fmt.Errorf("failed to load TPM keys: %v", err)
		}
		akchain, ikchain, err = loadTpmCerts(paths)
		if err != nil {
			return nil, fmt.Errorf("failed to load TPM certificates: %v", err)
		}
	}

	tpm := &Tpm{
		Pcrs:           pcrs,
		UseIma:         c.UseIma,
		ImaPcr:         c.ImaPcr,
		SigningCerts:   ikchain,
		MeasuringCerts: akchain,
	}

	return tpm, nil
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
		return ar.TpmMeasurement{}, fmt.Errorf("failed to get TPM Measurement: %v", err)
	}

	log.Trace("Collected TPM Quote")

	hashChain := make([]*ar.HashChainElem, len(t.Pcrs))
	for i, num := range t.Pcrs {

		hashChain[i] = &ar.HashChainElem{
			Type:   "Hash Chain",
			Pcr:    int32(num),
			Sha256: []ar.HexByte{pcrValues[num].Digest}}
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
			}
		}
	}

	tm := ar.TpmMeasurement{
		Type:      "TPM Measurement",
		HashChain: hashChain,
		Message:   quote.Quote,
		Signature: quote.Signature,
		Certs:     t.MeasuringCerts,
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

func (t *Tpm) Lock() {
	log.Trace("Trying to get lock for TPM")
	t.Mu.Lock()
	log.Trace("Got lock for TPM")
}

func (t *Tpm) Unlock() {
	log.Trace("Releasing TPM Lock")
	t.Mu.Unlock()
	log.Trace("Released TPM Lock")
}

// GetSigningKeys returns the IK private and public key as a generic
// crypto interface
func (t *Tpm) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {

	if ik == nil {
		return nil, nil, fmt.Errorf("failed to get IK Signer: not initialized")
	}
	priv, err := ik.Private(ik.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get IK Private")
	}

	return priv, ik.Public(), nil
}

func (t *Tpm) GetCertChain() ar.CertChain {
	return t.SigningCerts
}

// IsTpmProvisioningRequired checks if the Storage Root Key (SRK) is persisted
// at 0x810000001 and the encrypted AK blob is present, which is used as an
// indicator that the TPM is provisioned and the AK can directly be loaded.
// This function uses the low-level go-tpm library directly as go-attestation
// does not provide such a functionality.
func IsTpmProvisioningRequired(paths *Paths) (bool, error) {

	if _, err := os.Stat(paths.Ak); err != nil {
		log.Info("TPM Provisioning (Credential Activation) REQUIRED")
		return true, nil
	}

	if _, err := os.Stat(paths.AkCert); err != nil {
		log.Info("TPM Provisioning (Credential Activation) REQUIRED")
		return true, nil
	}

	if _, err := os.Stat(paths.Ik); err != nil {
		log.Info("TPM Provisioning (Credential Activation) REQUIRED")
		return true, nil
	}

	if _, err := os.Stat(paths.IkCert); err != nil {
		log.Info("TPM Provisioning (Credential Activation) REQUIRED")
		return true, nil
	}

	if _, err := os.Stat(paths.Ca); err != nil {
		log.Info("TPM Provisioning (Credential Activation) REQUIRED")
		return true, nil
	}

	rwc, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return true, fmt.Errorf("failed to Open TPM. Check access rights to /dev/tpm0")
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
		return fmt.Errorf("activate credential failed: OpenTPM returned %v", err)
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
		return nil, fmt.Errorf("failed to get TPM info - %v", err)
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
		return nil, fmt.Errorf("failed to Decode AK Public: %v", err)
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
		return nil, fmt.Errorf("failed to Decode Creation Data: %v", err)
	}

	parentAlg := make([]byte, 2)
	binary.BigEndian.PutUint16(parentAlg, uint16(tpm2CreateData.ParentNameAlg))
	parentQualifiedName := append(parentAlg, tpm2CreateData.ParentQualifiedName.Digest.Value...)

	// QN_AK := H_AK(QN_Parent || NAME_AK)
	buf := append(parentQualifiedName[:], name[:]...)
	qualifiedNameDigest := sha256.Sum256(buf)
	qualifiedName := append(alg, qualifiedNameDigest[:]...)

	log.Debugf("AK Name:           %v", hex.EncodeToString(name[:]))
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
		return nil, nil, fmt.Errorf("failed to get TPM PCRs: %v", err)
	}
	log.Trace("Finished reading PCRs from TPM")

	// Retrieve quote and store quote data and signature in TPM measurement object
	quote, err := ak.QuotePCRs(TPM, nonce, attest.HashSHA256, pcrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TPM quote - %v", err)
	}
	log.Trace("Finished getting Quote from TPM")

	return pcrValues, quote, nil
}

func provisionTpm(provServerURL string, akCsr, ikCsr []byte) (ar.CertChain, ar.CertChain, error) {
	log.Debug("Performing TPM credential activation..")

	if TPM == nil {
		return ar.CertChain{}, ar.CertChain{}, errors.New("TPM is not openend")
	}
	if ek == nil || ak == nil || ik == nil {
		return ar.CertChain{}, ar.CertChain{}, errors.New("keys not created")
	}

	tpmInfo, err := GetTpmInfo()
	if err != nil {
		return ar.CertChain{}, ar.CertChain{}, fmt.Errorf("failed to retrieve TPM Info: %v", err)
	}

	secret, err := requestActivateCredential(TPM, *ak, ek[0], tpmInfo, provServerURL)
	if err != nil {
		return ar.CertChain{}, ar.CertChain{}, fmt.Errorf("request activate credential failed: %v", err)
	}

	// Return challenge to server
	resp, err := requestTpmCerts(provServerURL, secret, akCsr, ikCsr)
	if err != nil {
		return ar.CertChain{}, ar.CertChain{}, fmt.Errorf("failed to request tpm certs: %v", err)
	}

	if resp.Version != tpmProtocolVersion {
		return ar.CertChain{}, ar.CertChain{}, fmt.Errorf("tpm certs response protocol version (%v) does not match our protocol versio (%v)",
			resp.Version, tpmProtocolVersion)
	}

	return resp.AkCertChain, resp.IkCertChain, nil
}

func saveTpmData(c *Config, paths *Paths, akchain, ikchain *ar.CertChain) error {

	// Store the certificates on disk
	log.Tracef("New AK Cert %v: %v", paths.AkCert, string(akchain.Leaf))
	log.Tracef("New IK Cert %v: %v", paths.IkCert, string(ikchain.Leaf))

	// TODO currently only the same certificate chain is supported for AK and IK
	for i, inter := range akchain.Intermediates {
		path := path.Join(c.StoragePath, fmt.Sprintf("intermediate%v.pem", i))
		paths.Intermediates = append(paths.Intermediates, path)
		log.Tracef("New Intermediate Cert %v: %v", path, string(inter))
	}
	log.Tracef("New CA Cert %v: %v", paths.Ca, string(akchain.Ca))

	if err := os.WriteFile(paths.AkCert, akchain.Leaf, 0644); err != nil {
		return fmt.Errorf("failed to write file %v: %v", paths.AkCert, err)
	}
	if err := os.WriteFile(paths.IkCert, ikchain.Leaf, 0644); err != nil {
		return fmt.Errorf("failed to write %v: %v", paths.IkCert, err)
	}
	if len(paths.Intermediates) != len(akchain.Intermediates) {
		return errors.New("internal error: length of intermediate certificates does not match length of paths")
	}
	for i := range akchain.Intermediates {
		if err := os.WriteFile(paths.Intermediates[i], akchain.Intermediates[i], 0644); err != nil {
			return fmt.Errorf("failed to write  %v: %v", paths.Intermediates[i], err)
		}
	}
	if err := os.WriteFile(paths.Ca, akchain.Ca, 0644); err != nil {
		return fmt.Errorf("failed to write %v: %v", paths.Ca, err)
	}

	// Store the encrypted AK blob on disk
	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal AK returned %v", err)
	}
	if err := os.WriteFile(paths.Ak, akBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file %v: %v", paths.Ak, err)
	}

	// Store the encrypted IK blob on disk
	ikBytes, err := ik.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal IK returned %v", err)
	}
	if err := os.WriteFile(paths.Ik, ikBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file %v: %v", paths.Ik, err)
	}

	return nil
}

func loadTpmKeys(akFile, ikFile string) error {

	if TPM == nil {
		return errors.New("tpm is not opened")
	}

	log.Debug("Loading TPM keys..")

	akBytes, err := os.ReadFile(akFile)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %v", akFile, err)
	}
	ak, err = TPM.LoadAK(akBytes)
	if err != nil {
		return fmt.Errorf("LoadAK failed: %v", err)
	}

	log.Debug("Loaded AK")

	ikBytes, err := os.ReadFile(ikFile)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %v", ikFile, err)
	}
	ik, err = TPM.LoadKey(ikBytes)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	log.Debug("Loaded IK")

	return nil
}

func loadTpmCerts(paths *Paths) (ar.CertChain, ar.CertChain, error) {
	akchain := ar.CertChain{}
	ikchain := ar.CertChain{}
	var cert []byte
	var err error
	// AK
	log.Tracef("Loading AK cert from %v", paths.AkCert)
	if cert, err = os.ReadFile(paths.AkCert); err != nil {
		return akchain, ikchain, fmt.Errorf("failed to load AK cert from %v: %v", paths.AkCert, err)
	}
	akchain.Leaf = cert
	// IK
	log.Tracef("Loading IK cert from %v", paths.IkCert)
	if cert, err = os.ReadFile(paths.IkCert); err != nil {
		return akchain, ikchain, fmt.Errorf("failed to load IK cert from %v: %v", paths.IkCert, err)
	}
	ikchain.Leaf = cert
	// Intermediates
	for _, path := range paths.Intermediates {
		if cert, err = os.ReadFile(path); err != nil {
			return akchain, ikchain, fmt.Errorf("failed to load intermediate cert from %v: %v", path, err)
		}
		akchain.Intermediates = append(akchain.Intermediates, cert)
		// TODO currently only one CA supported for AK and IK
		ikchain.Intermediates = append(ikchain.Intermediates, cert)
	}
	// CA
	if cert, err = os.ReadFile(paths.Ca); err != nil {
		return akchain, ikchain, fmt.Errorf("failed to load CA cert from %v: %v", paths.Ca, err)
	}
	akchain.Ca = cert
	ikchain.Ca = cert

	return akchain, ikchain, nil
}

func createKeys(tpm *attest.TPM, keyConfig string) ([]attest.EK, *attest.AK, *attest.Key, error) {

	log.Debug("Loading EKs")

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load EKs - %v", err)
	}
	log.Tracef("Found %v EK(s)", len(eks))

	log.Debug("Creating new AK")
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create new AK - %v", err)
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
		return nil, nil, nil, fmt.Errorf("failed to create new IK Key, unknown key configuration: %v", keyConfig)
	}

	ik, err := tpm.NewKey(ak, ikConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create new IK key - %v", err)
	}

	return eks, ak, ik, nil
}

func requestActivateCredential(tpm *attest.TPM, ak attest.AK, ek attest.EK, tpmInfo *attest.TPMInfo, url string) ([]byte, error) {

	attestParams := ak.AttestationParameters()

	qn, err := GetAkQualifiedName()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AK qualified name: %v", err)
	}
	var qnSlice [32]byte
	copy(qnSlice[:], qn)

	acRequest := AcRequest{
		Version:         tpmProtocolVersion,
		AkQualifiedName: qnSlice,
		TpmInfo:         *tpmInfo,
		Ek:              ek,
		AkParams:        attestParams,
		IkParams:        ik.CertificationParameters(),
	}

	// send EK and Attestation Parameters including AK to the server
	acResponse, err := sendParams(acRequest, url)
	if err != nil {
		return nil, fmt.Errorf("send params failed: %v", err)
	}

	// Client decrypts the credential
	log.Debug("Activate Credential")

	if acResponse.Version != tpmProtocolVersion {
		return nil, fmt.Errorf("activate credential response protocol version (%v) does not match our protocol version (%v)",
			acResponse.Version, tpmProtocolVersion)
	}
	if acResponse.Ec.Credential == nil {
		return nil, errors.New("did not receive encrypted credential from server")
	}
	if acResponse.Ec.Secret == nil {
		return nil, errors.New("did not receive encrypted secret from server")
	}

	secret, err := ak.ActivateCredential(tpm, acResponse.Ec)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed: %v", err)
	}

	return secret, nil
}

func sendParams(acRequest AcRequest, url string) (*AcResponse, error) {

	var buf bytes.Buffer
	// Registers specific type for value transferred as interface
	gob.Register(rsa.PublicKey{})
	e := gob.NewEncoder(&buf)
	if err := e.Encode(acRequest); err != nil {
		return nil, fmt.Errorf("failed to send to server: %v", err)
	}

	log.Debug("Sending Credential Activation HTTP POST Request")
	resp, err := http.Post(url, "tpm/attestparams", &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed: HTTP Server responded %v: %v",
			resp.Status, string(b))
	}

	var acResponse AcResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&acResponse)

	return &acResponse, nil
}

func requestTpmCerts(url string, secret []byte, akCsr, ikCsr []byte) (AkCertResponse, error) {

	qn, err := GetAkQualifiedName()
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("failed to retrieve AK qualified name - %v", err)
	}
	var qnSlice [32]byte
	copy(qnSlice[:], qn)

	akCertRequest := AkCertRequest{
		Version:         tpmProtocolVersion,
		AkQualifiedName: qnSlice,
		Secret:          secret,
		AkCsr:           akCsr,
		IkCsr:           ikCsr,
	}

	var buf bytes.Buffer
	e := gob.NewEncoder(&buf)
	if err := e.Encode(akCertRequest); err != nil {
		return AkCertResponse{}, fmt.Errorf("failed to send akCertRequest to server: %v", err)
	}

	log.Debug("Sending AK Certificate HTTP POST Request")

	resp, err := http.Post(url, "tpm/akcert", &buf)
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("error sending params - %v", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("error sending params - %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return AkCertResponse{}, fmt.Errorf("request failed: HTTP Server responded %v: %v",
			resp.Status, string(b))
	}

	var akCertResponse AkCertResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&akCertResponse)

	return akCertResponse, nil
}

func getTpmPcrs(c *Config) ([]int, error) {

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
		t := new(ar.Type)
		err = c.Serializer.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if t.Type == "RTM Manifest" {
			err = c.Serializer.Unmarshal(payload, &rtmMan)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal data from RTM Manifest: %v", err)
			}
		} else if t.Type == "OS Manifest" {
			err = c.Serializer.Unmarshal(payload, &osMan)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal data from OS Manifest: %v", err)
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

func createCsrs(c *Config, ak *attest.AK, ik *attest.Key) (akCsr, ikCsr []byte, err error) {

	// Get device configuration from metadata
	for i, m := range c.Metadata {

		// Extract plain payload of metadata
		payload, err := c.Serializer.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata file to determine the type
		t := new(ar.Type)
		err = c.Serializer.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if t.Type == "Device Config" {
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

func createAkCsr(ak *attest.AK, params ar.CsrParams) ([]byte, error) {

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
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return tmp.Bytes(), nil
}

func createIkCsr(ik *attest.Key, params ar.CsrParams) ([]byte, error) {

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
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return tmp.Bytes(), nil
}

func exists(i int, arr []int) bool {
	for _, elem := range arr {
		if elem == i {
			return true
		}
	}
	return false
}

func createLocalStorage(storagePath string) (*Paths, error) {

	// Create storage folder for storage of internal data if not existing
	if _, err := os.Stat(storagePath); err != nil {
		if err := os.MkdirAll(storagePath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for internal data '%v': %v", storagePath, err)
		}
	}

	// Read existing intermediate certificates
	intermediates := make([]string, 0)
	index := 0
	for {
		path := path.Join(storagePath, fmt.Sprintf("intermediate%v.pem", index))
		if _, err := os.Stat(path); err == nil {
			log.Tracef("Adding %v", path)
			intermediates = append(intermediates, path)
		} else {
			log.Tracef("Finished adding intermediates")
			break
		}
		index += 1
	}

	paths := &Paths{
		Ak:            path.Join(storagePath, "ak_encrypted.json"),
		AkCert:        path.Join(storagePath, "ak_cert.pem"),
		Ik:            path.Join(storagePath, "ik_encrypted.json"),
		IkCert:        path.Join(storagePath, "ik_cert.pem"),
		Intermediates: intermediates,
		Ca:            path.Join(storagePath, "ca.pem"),
	}

	return paths, nil
}
