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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sort"
	"sync"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/ima"
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

// Certs contains the TPM certificate chain for the AK and TLS key.
// This is not the TPM EK certificate chain but the certificate
// chain that was created during TPM credential activation
type Certs struct {
	Ak          []byte
	TLSCert     []byte
	DeviceSubCa []byte
	Ca          []byte
}

// AcRequest holds the data for an activate credential request
// for verifying that the AK and TLS Key were created on a genuine
// TPM with a valid EK
type AcRequest struct {
	AkQualifiedName [32]byte
	TpmInfo         attest.TPMInfo
	Ek              attest.EK
	AkParams        attest.AttestationParameters
	TLSKeyParams    attest.CertificationParameters
}

// AcResponse holds the activate credential challenge
type AcResponse struct {
	AkQualifiedName [32]byte
	Ec              attest.EncryptedCredential
}

// AkCertRequest holds the secret from the activate
// credential challenge as well as certificate parameters
// of the to be generated certificates (as the AK can only sign
// objects form within the TPM, a CSR is not possible)
type AkCertRequest struct {
	AkQualifiedName [32]byte
	Secret          []byte
	CertParams      [][]byte
}

// AkCertResponse holds the issued certificates including the
// certificate chain up to a Root CA
type AkCertResponse struct {
	AkQualifiedName [32]byte
	Certs           Certs
}

// Paths specifies the paths to store the encrypted TPM key blobs
// and the certificates
type Paths struct {
	Ak          string
	TLSKey      string
	AkCert      string
	TLSCert     string
	DeviceSubCa string
	Ca          string
}

var (
	TPM    *attest.TPM = nil
	ak     *attest.AK  = nil
	tlsKey *attest.Key = nil
	ek     []attest.EK
)

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

	// Load relevant parameters from the metadata files
	certParams, err := getTpmCertParams(c)
	if err != nil {
		return nil, fmt.Errorf("failed to load TPM cert params: %v", err)
	}
	pcrs, err := getTpmPcrs(c)
	if err != nil {
		return nil, fmt.Errorf("failed retrieve TPM PCRs: %v", err)
	}

	// Check if the TPM is provisioned. If provisioned, load the AK and TLS key.
	// Otherwise perform credential activation with provisioning server and then load the keys
	provisioningRequired, err := IsTpmProvisioningRequired(paths.Ak)
	if err != nil {
		return nil, fmt.Errorf("failed to check if TPM is provisioned: %v", err)
	}

	err = OpenTpm()
	if err != nil {
		return nil, fmt.Errorf("failed to open the TPM. Check if you have privileges to open /dev/tpm0: %v", err)
	}

	var certs Certs
	if provisioningRequired {

		log.Info("Provisioning TPM (might take a while)..")
		ek, ak, tlsKey, err = createKeys(TPM, c.KeyConfig)
		if err != nil {
			return nil, fmt.Errorf("activate credential failed: createKeys returned %v", err)
		}

		certs, err = provisionTpm(c.ServerAddr+"activate-credential/", certParams)
		if err != nil {
			return nil, fmt.Errorf("failed to provision TPM: %v", err)
		}

		err = saveTpmData(paths, &certs)
		if err != nil {
			os.Remove(paths.Ak)
			os.Remove(paths.TLSKey)
			return nil, fmt.Errorf("failed to save TPM data: %v", err)
		}

	} else {
		err = loadTpmKeys(paths.Ak, paths.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load TPM keys: %v", err)
		}
		certs, err = loadTpmCerts(paths)
		if err != nil {
			return nil, fmt.Errorf("failed to load TPM certificates: %v", err)
		}

	}

	tpm := &Tpm{
		Pcrs:   pcrs,
		UseIma: c.UseIma,
		ImaPcr: c.ImaPcr,
		SigningCerts: ar.CertChain{
			Leaf:          certs.TLSCert,
			Intermediates: [][]byte{certs.DeviceSubCa},
			Ca:            certs.Ca,
		},
		MeasuringCerts: ar.CertChain{
			Leaf:          certs.Ak,
			Intermediates: [][]byte{certs.DeviceSubCa},
			Ca:            certs.Ca,
		},
	}

	return tpm, nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (t *Tpm) Measure(nonce []byte) (ar.Measurement, error) {

	if t == nil {
		return ar.TpmMeasurement{}, fmt.Errorf("internal error: tpm object not initialized")
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

	for i, elem := range tm.HashChain {
		for _, sha := range elem.Sha256 {
			log.Debug(fmt.Sprintf("[%v], PCR%v: %v\n", i, elem.Pcr, hex.EncodeToString(sha)))
		}
	}
	log.Debug("Quote: ", hex.EncodeToString(tm.Message))
	log.Debug("Signature: ", hex.EncodeToString(tm.Signature))

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

// GetSigningKeys returns the TLS private and public key as a generic
// crypto interface
func (t *Tpm) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {

	if tlsKey == nil {
		return nil, nil, fmt.Errorf("failed to get TLS Key Signer: not initialized")
	}
	priv, err := tlsKey.Private(tlsKey.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS Key Private")
	}

	return priv, tlsKey.Public(), nil
}

func (t *Tpm) GetCertChain() ar.CertChain {
	return t.SigningCerts
}

// IsTpmProvisioningRequired checks if the Storage Root Key (SRK) is persisted
// at 0x810000001 and the encrypted AK blob is present, which is used as an
// indicator that the TPM is provisioned and the AK can directly be loaded.
// This function uses the low-level go-tpm library directly as go-attestation
// does not provide such a functionality.
func IsTpmProvisioningRequired(ak string) (bool, error) {

	if _, err := os.Stat(ak); err != nil {
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

// GetAkQualifiedName gets the Attestation Key Qualified Name which is the
// hash of the public area of the key concatenated with the qualified names
// of all parent keys. This name acts as the unique identifier for the AK
// TODO check calculation again
func GetAkQualifiedName() ([32]byte, error) {

	var qualifiedName [32]byte

	if TPM == nil {
		return qualifiedName, fmt.Errorf("failed to get AK Qualified Name - TPM is not opened")
	}
	if ak == nil {
		return qualifiedName, fmt.Errorf("failed to get AK Qualified Name - AK does not exist")
	}

	// This is a TPMT_PUBLIC structure
	pub := ak.AttestationParameters().Public

	// TPMT_PUBLIC Contains algorithm used for hashing the public area to get
	// the name (nameAlg)
	tpm2Pub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return qualifiedName, fmt.Errorf("failed to Decode AK Public - %v", err)
	}

	if tpm2Pub.NameAlg != tpm2.AlgSHA256 {
		return qualifiedName, errors.New("failed to Get AK public - unsupported hash algorithm")
	}

	// Name of object is nameAlg || Digest(TPMT_PUBLIC)
	alg := make([]byte, 2)
	binary.LittleEndian.PutUint16(alg, uint16(tpm2Pub.NameAlg))
	digestPub := sha256.Sum256(pub)
	name := append(alg, digestPub[:]...)

	log.Debug("Name: ", hex.EncodeToString(name[:]))

	// TPMS_CREATION_DATA contains parentQualifiedName
	createData := ak.AttestationParameters().CreateData
	tpm2CreateData, err := tpm2.DecodeCreationData(createData)
	if err != nil {
		return qualifiedName, fmt.Errorf("failed to Decode Creation Data: %v", err)
	}
	parentQualifiedName := tpm2CreateData.ParentQualifiedName.Digest.Value

	log.Trace("Parent Name: ", hex.EncodeToString(tpm2CreateData.ParentName.Digest.Value))
	log.Trace("Parent Qualified Name: ", hex.EncodeToString(parentQualifiedName))

	// QN_AK := H_AK(QN_Parent || NAME_AK)
	buf := append(parentQualifiedName[:], name[:]...)
	qualifiedName = sha256.Sum256(buf)

	log.Debug("AK Qualified Name: ", hex.EncodeToString(qualifiedName[:]))

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

func provisionTpm(provServerURL string, certParams [][]byte) (Certs, error) {
	log.Debug("Performing TPM credential activation..")

	if TPM == nil {
		return Certs{}, fmt.Errorf("failed to provision TPM - TPM is not openend")
	}
	if ek == nil || ak == nil || tlsKey == nil {
		return Certs{}, fmt.Errorf("failed to provision TPM - keys not created")
	}

	tpmInfo, err := GetTpmInfo()
	if err != nil {
		return Certs{}, fmt.Errorf("failed to retrieve TPM Info - %v", err)
	}

	secret, err := activateCredential(TPM, *ak, ek[0], tpmInfo, provServerURL)
	if err != nil {
		return Certs{}, fmt.Errorf("activate credential failed: activateCredential returned %v", err)
	}

	// Return challenge to server
	resp, err := requestTpmCerts(provServerURL, secret, certParams)
	if err != nil {
		return Certs{}, fmt.Errorf("activate credential failed: requestAkCert returned %v", err)
	}

	return resp.Certs, nil
}

func saveTpmData(paths *Paths, certs *Certs) error {
	// Store the certificates on disk
	log.Tracef("New AK Cert %v: %v", paths.AkCert, string(certs.Ak))
	log.Tracef("New TLS Key Cert %v: %v", paths.TLSCert, string(certs.TLSCert))
	log.Tracef("New Device Sub CA Cert %v: %v", paths.DeviceSubCa, string(certs.DeviceSubCa))
	log.Tracef("New Device CA Cert %v: %v", paths.Ca, string(certs.Ca))
	if err := ioutil.WriteFile(paths.AkCert, certs.Ak, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.AkCert, err)
	}
	if err := ioutil.WriteFile(paths.TLSCert, certs.TLSCert, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.TLSCert, err)
	}
	if err := ioutil.WriteFile(paths.DeviceSubCa, certs.DeviceSubCa, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.DeviceSubCa, err)
	}
	if err := ioutil.WriteFile(paths.Ca, certs.Ca, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.Ca, err)
	}

	// Store the encrypted AK blob on disk
	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal AK returned %v", err)
	}
	if err := ioutil.WriteFile(paths.Ak, akBytes, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.Ak, err)
	}

	// Store the encrypted TLS Key blob on disk
	tlsKeyBytes, err := tlsKey.Marshal()
	if err != nil {
		return fmt.Errorf("activate credential failed: Marshal TLS Key returned %v", err)
	}
	if err := ioutil.WriteFile(paths.TLSKey, tlsKeyBytes, 0644); err != nil {
		return fmt.Errorf("activate credential failed: WriteFile %v returned %v", paths.TLSKey, err)
	}

	return nil
}

func loadTpmKeys(akFile, tlsKeyFile string) error {

	if TPM == nil {
		return fmt.Errorf("failed to load keys - TPM is not opened")
	}

	log.Debug("Loading TPM keys..")

	akBytes, err := ioutil.ReadFile(akFile)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %v", akFile, err)
	}
	ak, err = TPM.LoadAK(akBytes)
	if err != nil {
		return fmt.Errorf("LoadAK failed: %v", err)
	}

	log.Debug("Loaded AK")

	tlsKeyBytes, err := ioutil.ReadFile(tlsKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read file %v: %v", tlsKeyFile, err)
	}
	tlsKey, err = TPM.LoadKey(tlsKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	log.Debug("Loaded TLS Key")

	return nil
}

func loadTpmCerts(paths *Paths) (Certs, error) {
	var certs Certs
	var cert []byte
	var err error
	// AK
	if cert, err = ioutil.ReadFile(paths.AkCert); err != nil {
		return certs, fmt.Errorf("failed to load AK cert from %v: %v", paths.AkCert, err)
	}
	certs.Ak = cert
	// TLS
	if cert, err = ioutil.ReadFile(paths.TLSCert); err != nil {
		return certs, fmt.Errorf("failed to load TLS cert from %v: %v", paths.TLSCert, err)
	}
	certs.TLSCert = cert
	//SubCA
	if cert, err = ioutil.ReadFile(paths.DeviceSubCa); err != nil {
		return certs, fmt.Errorf("failed to load Device Sub CA cert from %v: %v", paths.DeviceSubCa, err)
	}
	certs.DeviceSubCa = cert
	//CA
	if cert, err = ioutil.ReadFile(paths.Ca); err != nil {
		return certs, fmt.Errorf("failed to load CA cert from %v: %v", paths.Ca, err)
	}
	certs.Ca = cert

	return certs, nil
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

	log.Debug("Creating new TLS Key")

	// Create key as specified in the config file
	tlsKeyConfig := &attest.KeyConfig{}
	switch keyConfig {
	case "EC256":
		tlsKeyConfig.Algorithm = attest.ECDSA
		tlsKeyConfig.Size = 256
	case "EC384":
		tlsKeyConfig.Algorithm = attest.ECDSA
		tlsKeyConfig.Size = 384
	case "EC521":
		tlsKeyConfig.Algorithm = attest.ECDSA
		tlsKeyConfig.Size = 521
	case "RSA2048":
		tlsKeyConfig.Algorithm = attest.RSA
		tlsKeyConfig.Size = 2048
	case "RSA4096":
		tlsKeyConfig.Algorithm = attest.RSA
		tlsKeyConfig.Size = 4096
	default:
		return nil, nil, nil, fmt.Errorf("failed to create new TLS Key, unknown key configuration: %v", keyConfig)
	}

	tlsKey, err := tpm.NewKey(ak, tlsKeyConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create new TLS key - %v", err)
	}

	return eks, ak, tlsKey, nil
}

func activateCredential(tpm *attest.TPM, ak attest.AK, ek attest.EK, tpmInfo *attest.TPMInfo, url string) ([]byte, error) {

	attestParams := ak.AttestationParameters()

	qn, err := GetAkQualifiedName()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AK qualified name - %v", err)
	}

	acRequest := AcRequest{
		AkQualifiedName: qn,
		TpmInfo:         *tpmInfo,
		Ek:              ek,
		AkParams:        attestParams,
		TLSKeyParams:    tlsKey.CertificationParameters(),
	}

	// send EK and Attestation Parameters including AK to the server
	acResponse, err := sendParams(acRequest, url)
	if err != nil {
		return nil, fmt.Errorf("send params failed - %v", err)
	}

	// Client decrypts the credential
	log.Debug("Activate Credential")

	if acResponse.Ec.Credential == nil {
		return nil, fmt.Errorf("did not receive encrypted credential from server")
	}
	if acResponse.Ec.Secret == nil {
		return nil, fmt.Errorf("did not receive encrypted secret from server")
	}

	secret, err := ak.ActivateCredential(tpm, acResponse.Ec)
	if err != nil {
		return nil, fmt.Errorf("error activating credential - %v", err)
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
		return nil, fmt.Errorf("error sending params - %v", err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error sending params - %v", err)
	}

	var acResponse AcResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&acResponse)

	return &acResponse, nil
}

func requestTpmCerts(url string, secret []byte, certParams [][]byte) (AkCertResponse, error) {

	qn, err := GetAkQualifiedName()
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("failed to retrieve AK qualified name - %v", err)
	}

	akCertRequest := AkCertRequest{
		AkQualifiedName: qn,
		Secret:          secret,
		CertParams:      certParams,
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

	if resp.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(resp.Body)
		log.Warn("Request failed: body: ", string(b))
		return AkCertResponse{}, fmt.Errorf("request failed: HTTP Server responded '%v'", resp.Status)
	}

	log.Debug("HTTP Response OK")

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("error sending params - %v", err)
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
	log.Debug("Parsing ", len(rtmMan.Verifications), " RTM verifications")
	for _, ver := range rtmMan.Verifications {
		if ver.Type != "TPM Verification" || ver.Pcr == nil {
			continue
		}
		if !exists(*ver.Pcr, pcrs) {
			pcrs = append(pcrs, *ver.Pcr)
		}
	}
	log.Debug("Parsing ", len(osMan.Verifications), " OS verifications")
	for _, ver := range osMan.Verifications {
		if ver.Type != "TPM Verification" || ver.Pcr == nil {
			continue
		}
		if !exists(*ver.Pcr, pcrs) {
			pcrs = append(pcrs, *ver.Pcr)
		}
	}

	sort.Ints(pcrs)

	return pcrs, nil
}

func getTpmCertParams(c *Config) ([][]byte, error) {

	certParams := make([][]byte, 0)
	for i, m := range c.Metadata {

		// Extract plain payload (i.e. the manifest/description itself)
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

		if t.Type == "AK Cert Params" {
			certParams = append(certParams, m)
		} else if t.Type == "TLS Key Cert Params" {
			certParams = append(certParams, m)
		}
	}

	return certParams, nil
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

	paths := &Paths{
		Ak:          path.Join(storagePath, "ak_encrypted.json"),
		AkCert:      path.Join(storagePath, "ak_cert.pem"),
		TLSKey:      path.Join(storagePath, "tls_key_encrypted.json"),
		TLSCert:     path.Join(storagePath, "tls_cert.pem"),
		DeviceSubCa: path.Join(storagePath, "device_sub_ca.pem"),
		Ca:          path.Join(storagePath, "ca.pem"),
	}

	return paths, nil
}
