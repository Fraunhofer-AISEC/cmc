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

	"github.com/Fraunhofer-AISEC/go-attestation/attest"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/ima"
)

type Tpm struct{}

type AcRequest struct {
	AkQualifiedName [32]byte
	TpmInfo         attest.TPMInfo
	Ek              attest.EK
	AkParams        attest.AttestationParameters
	TlsKeyParams    attest.CertificationParameters
}

type AcResponse struct {
	AkQualifiedName [32]byte
	Ec              attest.EncryptedCredential
}

type AkCertRequest struct {
	AkQualifiedName [32]byte
	Secret          []byte
	CertParams      [][]byte
}

type AkCertResponse struct {
	AkQualifiedName [32]byte
	AkCert          []byte
	TlsCert         []byte
	DeviceSubCaCert []byte
	CaCert          []byte
}

// During TPM provisioning, store the encrypted TPM key blobs
// and the certificate chain in the locations specified by
// this structure
type Paths struct {
	Ak          string
	TlsKey      string
	AkCert      string
	TlsCert     string
	DeviceSubCa string
	Ca          string
}

var (
	tpm    *attest.TPM = nil
	ak     *attest.AK  = nil
	tlsKey *attest.Key = nil
	ek     []attest.EK
)

// Checks if the Storage Root Key (SRK) is persisted at 0x810000001
// and the encrypted AK blob is present, which is used as an
// indicator that the TPM is provisioned and the AK can directly
// be loaded. This function uses the low-level go-tpm library
// directly as go-attestation does not provide such a functionality.
func IsTpmProvisioningRequired(ak string) (bool, error) {

	if _, err := os.Stat(ak); err != nil {
		log.Info("TPM Provisioning (Credential Activation) REQUIRED")
		return true, nil
	}

	rwc, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return true, fmt.Errorf("Failed to Open TPM. Check access rights to /dev/tpm0")
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

// Opens the TPM and stores the handle internally
func OpenTpm() error {
	log.Debug("Opening TPM")

	if tpm != nil {
		return fmt.Errorf("Failed to open TPM - already open")
	}

	var err error
	config := &attest.OpenConfig{}
	tpm, err = attest.OpenTPM(config)
	if err != nil {
		tpm = nil
		return fmt.Errorf("Activate Credential failed: OpenTPM returned %v", err)
	}

	return nil
}

// Closes the TPM
func CloseTpm() error {
	if tpm == nil {
		return fmt.Errorf("Failed to close TPM - TPM is not openend")
	}
	tpm.Close()
	tpm = nil
	return nil
}

// Retrieve general TPM infos
func GetTpmInfo() (*attest.TPMInfo, error) {

	if tpm == nil {
		return nil, fmt.Errorf("Failed to Get TPM info - TPM is not openend")
	}

	tpmInfo, err := tpm.Info()
	if err != nil {
		return nil, fmt.Errorf("Failed to get TPM info - %v", err)
	}

	log.Debug("Version             : ", tpmInfo.Version)
	log.Debug("FirmwareVersionMajor: ", tpmInfo.FirmwareVersionMajor)
	log.Debug("FirmwareVersionMinor: ", tpmInfo.FirmwareVersionMinor)
	log.Debug("Interface           : ", tpmInfo.Interface)
	log.Debug("Manufacturer        : ", tpmInfo.Manufacturer.String())

	return tpmInfo, nil
}

// Gets the Attestation Key Qualified Name which is the hash of the public area
// of the key concatenated with the qualified names of all parent keys. This
// name acts as the unique identifier for the AK
// TODO check calculation again
func GetAkQualifiedName() ([32]byte, error) {

	var qualifiedName [32]byte

	if tpm == nil {
		return qualifiedName, fmt.Errorf("Failed to get AK Qualified Name - TPM is not opened")
	}
	if ak == nil {
		return qualifiedName, fmt.Errorf("Failed to get AK Qualified Name - AK does not exist")
	}

	// This is a TPMT_PUBLIC structure
	pub := ak.AttestationParameters().Public

	// TPMT_PUBLIC Contains algorithm used for hashing the public area to get
	// the name (nameAlg)
	tpm2Pub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return qualifiedName, fmt.Errorf("Failed to Decode AK Public - %v", err)
	}

	if tpm2Pub.NameAlg != tpm2.AlgSHA256 {
		return qualifiedName, errors.New("Failed to Get AK public - unsupported hash algorithm")
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
		return qualifiedName, fmt.Errorf("Failed to Decode Creation Data: %v", err)
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

// Create EK, AK, and TLS key. Perform credential activation via the server
// and retrieve the resulting AK and TLS Key cert from the server
// Stores the encrypted blobs and the certificates on disk.
func ProvisionTpm(provServerUrl string, paths *Paths, certParams [][]byte) error {

	log.Info("Provisioning TPM (might take a while)..")

	if tpm == nil {
		return fmt.Errorf("Failed to provision TPM - TPM is not openend")
	}

	tpmInfo, err := GetTpmInfo()
	if err != nil {
		return fmt.Errorf("Failed to retrieve TPM Info - %v", err)
	}

	ek, ak, tlsKey, err = createKeys(tpm)
	if err != nil {
		return fmt.Errorf("Activate Credential failed: createKeys returned %v", err)
	}

	secret, err := activateCredential(tpm, *ak, ek[0], tpmInfo, provServerUrl)
	if err != nil {
		return fmt.Errorf("Activate Credential failed: activateCredential returned %v", err)
	}

	// Return challenge to server
	certs, err := requestTpmCerts(provServerUrl, secret, certParams)
	if err != nil {
		return fmt.Errorf("Activate Credential failed: requestAkCert returned %v", err)
	}

	// Store the certificates on disk
	log.Tracef("New AK Cert %v: %v", paths.AkCert, string(certs.AkCert))
	log.Tracef("New TLS Key Cert %v: %v", paths.TlsCert, string(certs.TlsCert))
	log.Tracef("New Device Sub CA Cert %v: %v", paths.DeviceSubCa, string(certs.DeviceSubCaCert))
	log.Tracef("New Device CA Cert %v: %v", paths.Ca, string(certs.CaCert))
	if err := ioutil.WriteFile(paths.AkCert, certs.AkCert, 0644); err != nil {
		return fmt.Errorf("Activate Credential failed: WriteFile %v returned %v", paths.AkCert, err)
	}
	if err := ioutil.WriteFile(paths.TlsCert, certs.TlsCert, 0644); err != nil {
		return fmt.Errorf("Activate Credential failed: WriteFile %v returned %v", paths.TlsCert, err)
	}
	if err := ioutil.WriteFile(paths.DeviceSubCa, certs.DeviceSubCaCert, 0644); err != nil {
		return fmt.Errorf("Activate Credential failed: WriteFile %v returned %v", paths.DeviceSubCa, err)
	}
	if err := ioutil.WriteFile(paths.Ca, certs.CaCert, 0644); err != nil {
		return fmt.Errorf("Activate Credential failed: WriteFile %v returned %v", paths.Ca, err)
	}

	// Store the encrypted AK blob on disk
	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("Activate Credential failed: Marshal AK returned %v", err)
	}
	if err := ioutil.WriteFile(paths.Ak, akBytes, 0644); err != nil {
		return fmt.Errorf("Activate Credential failed: WriteFile %v returned %v", paths.Ak, err)
	}

	// Store the encrypted TLS Key blob on disk
	tlsKeyBytes, err := tlsKey.Marshal()
	if err != nil {
		return fmt.Errorf("Activate Credential failed: Marshal TLS Key returned %v", err)
	}
	if err := ioutil.WriteFile(paths.TlsKey, tlsKeyBytes, 0644); err != nil {
		return fmt.Errorf("Activate Credential failed: WriteFile %v returned %v", paths.TlsKey, err)
	}

	return nil
}

// Load the attestation key and the TLS key
func LoadTpmKeys(akFile, tlsKeyFile string) error {

	if tpm == nil {
		return fmt.Errorf("Failed to load keys - TPM is not opened")
	}

	log.Debug("Loading TPM keys..")

	akBytes, err := ioutil.ReadFile(akFile)
	if err != nil {
		return fmt.Errorf("Load Keys failed: ReadFile %v returned %v", akFile, err)
	}
	ak, err = tpm.LoadAK(akBytes)
	if err != nil {
		return fmt.Errorf("LoadAK failed: %v", err)
	}

	log.Debug("Loaded AK")

	tlsKeyBytes, err := ioutil.ReadFile(tlsKeyFile)
	if err != nil {
		return fmt.Errorf("Load Key failed: ReadFile %v returned %v", tlsKeyFile, err)
	}
	tlsKey, err = tpm.LoadKey(tlsKeyBytes)
	if err != nil {
		return fmt.Errorf("LoadKey failed: %v", err)
	}

	log.Debug("Loaded TLS Key")

	return nil
}

// Implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (t Tpm) Measure(mp ar.MeasurementParams) (ar.Measurement, error) {

	tpmParams, ok := mp.(ar.TpmParams)
	if !ok {
		return ar.TpmMeasurement{}, fmt.Errorf("Failed to retrieve TPM params - invalid type")
	}

	pcrValues, quote, err := GetTpmMeasurement(tpmParams.Nonce, tpmParams.Pcrs)
	if err != nil {
		return ar.TpmMeasurement{}, fmt.Errorf("Failed to get TPM Measurement: %v", err)
	}

	hashChain := make([]*ar.HashChainElem, len(tpmParams.Pcrs))
	for i, num := range tpmParams.Pcrs {

		hashChain[i] = &ar.HashChainElem{
			Type:   "Hash Chain",
			Pcr:    int32(num),
			Sha256: []string{hex.EncodeToString(pcrValues[num].Digest)}}
	}

	if tpmParams.UseIma {
		// If the IMA is used, not the final PCR value is sent but instead
		// a list of the kernel modules which are extended during verification
		// to result in the final value
		imaDigests, err := ima.GetImaRuntimeDigests()
		if err != nil {
			log.Error("Failed to get IMA runtime digests. Ignoring..")
		}

		imaDigestsHex := make([]string, 0)
		for _, elem := range imaDigests {
			imaDigestsHex = append(imaDigestsHex, hex.EncodeToString(elem[:]))
		}

		// Find the IMA PCR in the TPM Measurement
		for _, elem := range hashChain {
			if elem.Pcr == tpmParams.ImaPcr {
				elem.Sha256 = imaDigestsHex
			}
		}
	}

	tm := ar.TpmMeasurement{
		Type:      "TPM Measurement",
		HashChain: hashChain,
		Message:   hex.EncodeToString(quote.Quote),
		Signature: hex.EncodeToString(quote.Signature),
		Certs:     tpmParams.Certs,
	}

	for i, elem := range tm.HashChain {
		log.Debug(fmt.Sprintf("[%v], PCR%v: %v\n", i, elem.Pcr, elem.Sha256))
	}
	log.Debug(tm.Message)
	log.Debug(tm.Signature)

	return tm, nil
}

// Retrieves the specified PCRs as well as a Quote over the PCRs
// and returnes it as an attestationreport TPM Measurement object
func GetTpmMeasurement(nonce []byte, pcrs []int) ([]attest.PCR, *attest.Quote, error) {

	if tpm == nil {
		return nil, nil, fmt.Errorf("Failed to retrieve quote - TPM is not opened")
	}
	if ak == nil {
		return nil, nil, fmt.Errorf("Failed to retrieve quote - AK does not exist")
	}

	// Read and Store PCRs into TPM Measurement structure
	pcrValues, err := tpm.PCRs(attest.HashSHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to retrieve TPM PCRs")
	}

	// Retrieve quote and store quote data and signature in TPM measurement object
	quote, err := ak.QuotePCRs(tpm, nonce, attest.HashSHA256, pcrs)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to retrieve quote - %v", err)
	}

	return pcrValues, quote, nil
}

func createKeys(tpm *attest.TPM) ([]attest.EK, *attest.AK, *attest.Key, error) {

	log.Debug("Loading EKs")

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to load EKs - %v", err)
	}

	log.Tracef("Found %v EKs", len(eks))
	for _, ek := range eks {
		if ek.Certificate != nil {
			log.Tracef("EK Certificate: %v", string(ek.Certificate.Raw))
		}
		log.Tracef("EK Certificate URL %v", ek.CertificateURL)
	}

	log.Debug("Creating new AK")
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to create new AK - %v", err)
	}

	log.Debug("Creating new TLS Key")

	tlsKeyConfig := &attest.KeyConfig{
		Algorithm: attest.RSA,
		Size:      2048,
	}
	tlsKey, err := tpm.NewKey(ak, tlsKeyConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to create new TLS key - %v", err)
	}

	return eks, ak, tlsKey, nil
}

func activateCredential(tpm *attest.TPM, ak attest.AK, ek attest.EK, tpmInfo *attest.TPMInfo, url string) ([]byte, error) {

	attestParams := ak.AttestationParameters()

	qn, err := GetAkQualifiedName()
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve AK qualified name - %v", err)
	}

	acRequest := AcRequest{
		AkQualifiedName: qn,
		TpmInfo:         *tpmInfo,
		Ek:              ek,
		AkParams:        attestParams,
		TlsKeyParams:    tlsKey.CertificationParameters(),
	}

	// send EK and Attestation Parameters including AK to the server
	acResponse, err := sendParams(acRequest, url)
	if err != nil {
		return nil, fmt.Errorf("Send params failed - %v", err)
	}

	// Client decrypts the credential
	log.Debug("Activate Credential")

	if acResponse.Ec.Credential == nil {
		return nil, fmt.Errorf("Did not receive encrypted credential from server")
	}
	if acResponse.Ec.Secret == nil {
		return nil, fmt.Errorf("Did not receive encrypted secret from server")
	}

	secret, err := ak.ActivateCredential(tpm, acResponse.Ec)
	if err != nil {
		return nil, fmt.Errorf("Error activating credential - %v", err)
	}

	return secret, nil
}

func sendParams(acRequest AcRequest, url string) (*AcResponse, error) {

	var buf bytes.Buffer
	// Registers specific type for value transferred as interface
	gob.Register(rsa.PublicKey{})
	e := gob.NewEncoder(&buf)
	if err := e.Encode(acRequest); err != nil {
		return nil, fmt.Errorf("Failed to send to server: %v", err)
	}

	log.Debug("Sending Credential Activation HTTP POST Request")
	resp, err := http.Post(url, "tpm/attestparams", &buf)
	if err != nil {
		return nil, fmt.Errorf("Error sending params - %v", err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error sending params - %v", err)
	}

	var acResponse AcResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&acResponse)

	return &acResponse, nil
}

func requestTpmCerts(url string, secret []byte, certParams [][]byte) (AkCertResponse, error) {

	qn, err := GetAkQualifiedName()
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("Failed to retrieve AK qualified name - %v", err)
	}

	akCertRequest := AkCertRequest{
		AkQualifiedName: qn,
		Secret:          secret,
		CertParams:      certParams,
	}

	var buf bytes.Buffer
	e := gob.NewEncoder(&buf)
	if err := e.Encode(akCertRequest); err != nil {
		return AkCertResponse{}, fmt.Errorf("Failed to send akCertRequest to server: %v", err)
	}

	log.Debug("Sending AK Certificate HTTP POST Request")

	resp, err := http.Post(url, "tpm/akcert", &buf)
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("Error sending params - %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(resp.Body)
		log.Warn("Request failed: body: ", string(b))
		return AkCertResponse{}, fmt.Errorf("Request Failed: HTTP Server responded '%v'", resp.Status)
	}

	log.Debug("HTTP Response OK")

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return AkCertResponse{}, fmt.Errorf("Error sending params - %v", err)
	}

	var akCertResponse AkCertResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&akCertResponse)

	return akCertResponse, nil
}

func GetTlsKey() (crypto.PrivateKey, crypto.PublicKey, error) {

	if tlsKey == nil {
		return nil, nil, fmt.Errorf("Failed to get TLS Key Signer: not initialized")
	}

	priv, err := tlsKey.Private(tlsKey.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get TLS Key Private")
	}

	return priv, tlsKey.Public(), nil
}
