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

package main

// Install github packages with "go get [url]"
import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"

	"encoding/hex"
	"encoding/json"
	"flag"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/square/go-jose.v2"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
	pc "github.com/Fraunhofer-AISEC/cmc/provclient"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/fsnotify/fsnotify"
)

type config struct {
	ServerAddr string `json:"provServerAddr"`
	ServerPath string `json:"serverPath"`
	LocalPath  string `json:"localPath"`
	UseIma     bool   `json:"useIma"`
	ImaPcr     int32  `json:"imaPcr"`
	// Key config: RSA2048 RSA4096 EC256 EC384 EC521
	KeyConfig  string `json:"keyConfig,omitempty"` // Default defined below during parsing

	internalPath    string
	akPath          string
	akCertPath      string
	tlsKeyPath      string
	tlsCertPath     string
	deviceSubCaPath string
	caPath          string
}

// Certs contains the entire certificate chain for the device
type Certs struct {
	Ak          []byte
	TLSCert     []byte
	DeviceSubCa []byte
	Ca          []byte
}

// server is the gRPC server structure
type server struct {
	ci.UnimplementedCMCServiceServer
	// General config
	config config
	// Certificate chain for the device
	certs Certs
	// metadata (manifests and descriptions of the device)
	metadata [][]byte
	// PCRs to be included in the quote (calculated from manifests)
	pcrs []int
	// Certificate Signer roles to avoid impersonation attacks on certificates
	roles *ar.SignerRoles
	// TPM Driver struct (further drivers must also be registered here)
	tpm *tpmdriver.Tpm
}

func loadConfig(configFile string) (*config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read cmcd config file %v: %v", configFile, err)
	}
	// Default configuration
	c := &config {
		KeyConfig: "EC256",
	}
	// Obtain custom configuration
	err = json.Unmarshal(data, c)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse cmcd config: %v", err)
	}

	// Convert path to absolute paths (might already be absolute or relative to config file)
	// The filenames are just internal names for files retrieved over the
	// network during provisioning
	c.LocalPath = getFilePath(c.LocalPath, filepath.Dir(configFile))
	c.internalPath = path.Join(c.LocalPath, "internal")
	c.akPath = path.Join(c.internalPath, "ak_encrypted.json")
	c.akCertPath = path.Join(c.internalPath, "ak_cert.pem")
	c.tlsKeyPath = path.Join(c.internalPath, "tls_key_encrypted.json")
	c.tlsCertPath = path.Join(c.internalPath, "tls_cert.pem")
	c.deviceSubCaPath = path.Join(c.internalPath, "device_sub_ca.pem")
	c.caPath = path.Join(c.internalPath, "ca.pem")

	// Create 'internal' folder if not existing for storage of internal data
	if _, err := os.Stat(c.internalPath); err != nil {
		if err := os.MkdirAll(c.internalPath, 0755); err != nil {
			return nil, fmt.Errorf("Failed to create directory for internal data '%v': %v", c.internalPath, err)
		}
	}

	printConfig(c)

	return c, nil
}

func loadMetadata(dir string) (metadata [][]byte, certParams [][]byte, pcrs []int, err error) {
	// Read number of files
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to read metadata folder: %v", err)
	}

	// Retrieve the metadata files
	metadata = make([][]byte, 0)
	var rtmManifest []byte
	var osManifest []byte
	log.Tracef("Parsing %v metadata files in %v", len(files), dir)
	for i := 0; i < len(files); i++ {
		file := path.Join(dir, files[i].Name())
		if fileInfo, err := os.Stat(file); err == nil {
			if fileInfo.IsDir() {
				log.Tracef("Skipping directory %v", file)
				continue
			}
		}
		log.Tracef("Reading file %v", file)
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to read file %v: %v", file, err)
		}

		jws, err := jose.ParseSigned(string(data))
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}
		payload := jws.UnsafePayloadWithoutVerification()

		// Unmarshal the Type field of the JSON file to determine the type
		t := new(ar.JSONType)
		err = json.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object %v: %v", i, err)
			continue
		}

		if t.Type == "AK Cert Params" {
			certParams = append(certParams, data)
		} else if t.Type == "TLS Key Cert Params" {
			certParams = append(certParams, data)
		} else if t.Type == "RTM Manifest" {
			metadata = append(metadata, data)
			rtmManifest = data
		} else if t.Type == "OS Manifest" {
			metadata = append(metadata, data)
			osManifest = data
		} else {
			metadata = append(metadata, data)
		}
		log.Tracef("Found %v", t.Type)
	}

	pcrs = getPcrs(rtmManifest, osManifest)

	return metadata, certParams, pcrs, nil
}

func loadCerts(c *config) (Certs, error) {
	var certs Certs
	var cert []byte
	var err error
	// AK
	if cert, err = ioutil.ReadFile(c.akCertPath); err != nil {
		return certs, fmt.Errorf("Failed to load AK cert from %v: %v", c.akCertPath, err)
	}
	certs.Ak = cert
	// TLS
	if cert, err = ioutil.ReadFile(c.tlsCertPath); err != nil {
		return certs, fmt.Errorf("Failed to load TLS cert from %v: %v", c.tlsCertPath, err)
	}
	certs.TLSCert = cert
	//SubCA
	if cert, err = ioutil.ReadFile(c.deviceSubCaPath); err != nil {
		return certs, fmt.Errorf("Failed to load Device Sub CA cert from %v: %v", c.deviceSubCaPath, err)
	}
	certs.DeviceSubCa = cert
	//CA
	if cert, err = ioutil.ReadFile(c.caPath); err != nil {
		return certs, fmt.Errorf("Failed to load CA cert from %v: %v", c.caPath, err)
	}
	certs.Ca = cert

	return certs, nil
}

func watchFileChanges(watcher *fsnotify.Watcher, s *server) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			log.Tracef("file system event: %v", event)
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Tracef("modified file: %v", event.Name)
				metadata, _, pcrs, err := loadMetadata(s.config.LocalPath)
				if err != nil {
					return
				}
				s.metadata = metadata
				s.pcrs = pcrs
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}
}

func printConfig(c *config) {
	log.Info("Using the following configuration:")
	log.Info("\tConfiguration Server URL : ", c.ServerAddr)
	log.Info("\tConfiguration Server Path: ", c.ServerPath)
	log.Info("\tLocal Config Path        : ", c.LocalPath)
	log.Info("\tUse IMA                  : ", c.UseIma)
	log.Info("\tIMA PCR                  : ", c.ImaPcr)
	log.Info("\tInternal Data Path       : ", c.internalPath)
	log.Info("\tAK Encrypted Key Path    : ", c.akPath)
	log.Info("\tAK Certificate Path      : ", c.akCertPath)
	log.Info("\tTLS Key Encrypted Path   : ", c.tlsKeyPath)
	log.Info("\tTLS Key Certificate Path : ", c.tlsCertPath)
	log.Info("\tDevice Sub CA Cert Path  : ", c.deviceSubCaPath)
	log.Info("\tCA Certificate Path      : ", c.caPath)
}

func main() {

	log.SetFormatter(&log.TextFormatter{
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000",
	})

	log.SetLevel(log.TraceLevel)

	log.Info("Starting CMC")

	cmcPort := flag.String("port", "9955", "TCP Port to connect to the CMC daemon gRPC interface")
	configFile := flag.String("config", "", "configuration file")
	fetchMetadata := flag.Bool("fetch-metadata", false, "Request metadata from provisioning server")
	flag.Parse()

	if *configFile == "" {
		log.Error("Config file not specified. Please specify a config file")
		return
	}
	if _, err := os.Stat(*configFile); err != nil {
		log.Error("Config file '", *configFile, "' does not exist. Abort")
		return
	}

	log.Info("Using Config File ", *configFile)
	log.Info("Using CMC Port: ", *cmcPort)

	// Loading the configuration is a three step process:
	// 1. Load local initial cmcd configuration from config file. The config file contains
	// 		a provisioning server URL.
	// 2. Request the metadata from the provioning server. Store the
	//		metadata on disk. This step is optional and can be omitted if the metadata is available
	//      in 'localPath' as specified in the configuration file.
	// 3. Check if the TPM is provisioned. If not, create a new AK and TLS Key, contact the
	//      provisiong server and present EK, AK and TLS Key in order to get a new
	//      certificates. The certificates are stored on disk.

	// Step 1: Load the cmcd configuration from file
	c, err := loadConfig(*configFile)
	if err != nil {
		log.Errorf("Failed to load config: %v", err)
		return
	}

	// Step 2: Fetch device metadata from provisioning server and store it on disk, then load it
	if *fetchMetadata {
		err = pc.FetchMetadata(c.ServerAddr, c.ServerPath, c.LocalPath)
		if err != nil {
			log.Error("Failed to fetch device metadata from provisioning server")
			return
		}
	}

	metadata, certParams, pcrs, err := loadMetadata(c.LocalPath)
	if err != nil {
		log.Errorf("Failed to load metadata: %v", err)
		return
	}

	// Step 3: Check if the TPM is provisioned. If provisioned, load the AK.
	// Otherwise perform credential activation with CA server and then load the AK
	provisioningRequired, err := tpmdriver.IsTpmProvisioningRequired(c.akPath)
	if err != nil {
		log.Error("Failed to check if TPM is provisioned - ", err)
		return
	}

	err = tpmdriver.OpenTpm()
	if err != nil {
		log.Error("Failed to open the TPM. Check if you have privileges to open /dev/tpm0 - ", err)
		return
	}
	defer tpmdriver.CloseTpm()

	if provisioningRequired {
		paths := &tpmdriver.Paths{
			Ak:          c.akPath,
			TLSKey:      c.tlsKeyPath,
			AkCert:      c.akCertPath,
			TLSCert:     c.tlsCertPath,
			DeviceSubCa: c.deviceSubCaPath,
			Ca:          c.caPath,
		}
		err = tpmdriver.ProvisionTpm(c.ServerAddr+"activate-credential/", paths, certParams, c.KeyConfig)
		if err != nil {
			log.Error("Failed to provision TPM - ", err)
			os.Remove(c.akPath)
			os.Remove(c.tlsKeyPath)
			return
		}
	} else {
		err = tpmdriver.LoadTpmKeys(c.akPath, c.tlsKeyPath)
		if err != nil {
			log.Error("Failed to load TPM keys - ", err)
			return
		}
	}

	certs, err := loadCerts(c)
	if err != nil {
		log.Errorf("Failed to load certificates: %v", err)
		return
	}

	// The verification requires different roles for different certificate chains
	// to avoid impersonation
	roles := &ar.SignerRoles{
		ManifestSigners:    []string{"developer", "evaluator", "certifier"},
		CompanyDescSigners: []string{"operator", "evaluator", "certifier"},
		ArSigners:          []string{"device"},
		ConnDescSigners:    []string{"operator"},
	}

	server := &server{
		config:   *c,
		metadata: metadata,
		certs:    certs,
		pcrs:     pcrs,
		roles:    roles,
		tpm:      &tpmdriver.Tpm{},
	}

	// Run CMC<-> Container iface server
	err = run(cmcPort, server)
	if err != nil {
		log.Error(err)
		return
	}
}

func run(port *string, server *server) error {

	// Watch file system for metadata file changes
	log.Tracef("Registering watcher for file changes in %v", server.config.LocalPath)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("Failed to create watcher for file changes: %v", err)
	}
	defer watcher.Close()
	go watchFileChanges(watcher, server)
	err = watcher.Add(server.config.LocalPath)
	if err != nil {
		return fmt.Errorf("Failed to add watcher for file changes in %v", server.config.LocalPath)
	}

	// Create TCP server
	log.Info("Starting CMC Server..")
	addr := "127.0.0.1:" + *port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Failed to start server on %v: %v", addr, err)
	}

	// Start gRPC server
	s := grpc.NewServer()
	ci.RegisterCMCServiceServer(s, server)

	log.Infof("Waiting for requests on %v", listener.Addr())
	err = s.Serve(listener)
	if err != nil {
		return fmt.Errorf("Failed to serve: %v", err)
	}

	return nil
}

func (s *server) Attest(ctx context.Context, in *ci.AttestationRequest) (*ci.AttestationResponse, error) {

	log.Info("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(in.Nonce))

	tpmParams := ar.TpmParams{
		Nonce: in.Nonce,
		Pcrs:  s.pcrs,
		Certs: ar.TpmCerts{
			AkCert:        string(s.certs.Ak),
			Intermediates: []string{string(s.certs.DeviceSubCa)},
			CaCert:        string(s.certs.Ca),
		},
		UseIma: s.config.UseIma,
		ImaPcr: s.config.ImaPcr,
	}

	a := ar.Generate(in.Nonce, s.metadata, []ar.Measurement{s.tpm}, []ar.MeasurementParams{tpmParams})

	log.Info("Prover: Signing Attestation Report")
	tlsKeyPriv, tlsKeyPub, err := tpmdriver.GetTLSKey()
	if err != nil {
		log.Error("Prover: Failed to get TLS Key")
		return &ci.AttestationResponse{Status: ci.Status_FAIL}, nil
	}

	var status ci.Status
	certsPem := [][]byte{s.certs.TLSCert, s.certs.DeviceSubCa, s.certs.Ca}
	ok, data := ar.Sign(&s.tpm.Mu, a, tlsKeyPriv, tlsKeyPub, certsPem)
	if !ok {
		log.Error("Prover: Failed to sign Attestion Report ")
		status = ci.Status_FAIL
	} else {
		status = ci.Status_OK
	}

	log.Info("Prover: Finished")

	response := &ci.AttestationResponse{
		Status:            status,
		AttestationReport: data,
	}

	return response, nil
}

func (s *server) Verify(ctx context.Context, in *ci.VerificationRequest) (*ci.VerificationResponse, error) {

	var status ci.Status

	log.Info("Received Connection Request Type 'Verification Request'")

	log.Info("Verifier: Verifying Attestation Report")
	result := ar.Verify(string(in.AttestationReport), in.Nonce, s.certs.Ca, s.roles)

	log.Info("Verifier: Marshaling Attestation Result")
	data, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Verifier: Failed to marshal Attestation Result: %v", err)
		status = ci.Status_FAIL
	} else {
		status = ci.Status_OK
	}

	response := &ci.VerificationResponse{
		Status:             status,
		VerificationResult: data,
	}

	log.Info("Verifier: Finished")

	return response, nil
}

func (s *server) TLSSign(ctx context.Context, in *ci.TLSSignRequest) (*ci.TLSSignResponse, error) {
	var err error
	var sr *ci.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	// get sign opts
	opts, err = convertHash(in.GetHashtype(), in.GetPssOpts())
	if err != nil {
		log.Error("[Prover] Failed to choose requested hash function.", err.Error())
		return &ci.TLSSignResponse{Status: ci.Status_FAIL}, errors.New("Prover: Failed to find appropriate hash function")
	}
	// get key
	tlsKeyPriv, _, err = tpmdriver.GetTLSKey()
	if err != nil {
		log.Error("[Prover] Failed to get TLS key. ", err.Error())
		return &ci.TLSSignResponse{Status: ci.Status_FAIL}, errors.New("Prover: Failed to get TLS key")
	}
	// Sign
	// Convert crypto.PrivateKey to crypto.Signer
	log.Trace("[Prover] TLSSign using opts: ", opts )
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, in.GetContent(), opts)
	if err != nil {
		log.Error("[Prover] ", err.Error())
		return &ci.TLSSignResponse{Status: ci.Status_FAIL}, errors.New("Prover: Failed to perform Signing operation")
	}
	// Create response
	sr = &ci.TLSSignResponse{
		Status:        ci.Status_OK,
		SignedContent: signature,
	}
	// Return response
	log.Info("Prover: Performed Sign operation.")
	return sr, nil
}

// Loads public key for tls certificate
func (s *server) TLSCert(ctx context.Context, in *ci.TLSCertRequest) (*ci.TLSCertResponse, error) {
	var resp *ci.TLSCertResponse = &ci.TLSCertResponse{}
	if s.certs.TLSCert == nil {
		log.Error("Prover: TLS Certificate not found - was the device provisioned correctly?")
		return &ci.TLSCertResponse{Status: ci.Status_FAIL}, errors.New("No TLS Certificate obtained")
	}
	// provide TLS certificate chain
	resp.Certificate = [][]byte{s.certs.TLSCert, s.certs.DeviceSubCa}
	resp.Status = ci.Status_OK
	log.Info("Prover: Obtained TLS Cert.")
	return resp, nil
}

// Converts Protobuf hashtype to crypto.SignerOpts
func convertHash(hashtype ci.HashFunction, pssOpts *ci.PSSOptions) (crypto.SignerOpts, error) {
	var hash crypto.Hash
	var len int
	switch hashtype {
	case ci.HashFunction_SHA256:
		hash = crypto.SHA256
		len = 32
	case ci.HashFunction_SHA384:
		hash = crypto.SHA384
		len = 48
	case ci.HashFunction_SHA512:
		len = 64
		hash = crypto.SHA512
	default:
		return  crypto.SHA512, fmt.Errorf("[cmcd] Hash function not implemented: %v", hashtype)
	}
	if pssOpts != nil {
		saltlen := int(pssOpts.SaltLength)
		// go-attestation / go-tpm does not allow -1 as definition for length of hash
		if saltlen < 0 {
			log.Warning("Signature Options: Adapted RSA PSS Salt length to length of hash: ", len)
			saltlen = len
		}
		return &rsa.PSSOptions{SaltLength: saltlen, Hash: hash}, nil
	}
	return hash, nil
}

// Returns either the unmodified absolute path or the absolute path
// retrieved from a path relative to a base path
func getFilePath(p, base string) string {
	if path.IsAbs(p) {
		return p
	}
	ret, _ := filepath.Abs(filepath.Join(base, p))
	return ret
}

func getPcrs(rtmManifest, osManifest []byte) []int {

	// Unpack the signed RTM Manifest
	var rtmMan ar.RtmManifest
	jws, err := jose.ParseSigned(string(rtmManifest))
	if err != nil {
		log.Warn("Failed to parse RTM Manifest - ", err)
	} else {
		data := jws.UnsafePayloadWithoutVerification()
		err = json.Unmarshal(data, &rtmMan)
		if err != nil {
			log.Warn("Failed to unmarshal data from RTM Manifest - ", err)
		}
	}

	// Unpack the signed OS Manifest
	var osMan ar.OsManifest
	jws, err = jose.ParseSigned(string(osManifest))
	if err != nil {
		log.Warn("Failed to parse OS Manifest - ", err)
	} else {
		data := jws.UnsafePayloadWithoutVerification()
		err = json.Unmarshal(data, &osMan)
		if err != nil {
			log.Warn("Failed to unmarshal data from OS Manifst - ", err)
		}
	}

	// Generate the list of PCRs to be included in the quote
	pcrs := make([]int, 0)
	log.Debug("Parsing ", len(rtmMan.Verifications), " RTM verifications")
	for _, ver := range rtmMan.Verifications {
		if !exists(ver.Pcr, pcrs) {
			pcrs = append(pcrs, ver.Pcr)
		}
	}
	log.Debug("Parsing ", len(osMan.Verifications), " OS verifications")
	for _, ver := range osMan.Verifications {
		if !exists(ver.Pcr, pcrs) {
			pcrs = append(pcrs, ver.Pcr)
		}
	}

	sort.Ints(pcrs)

	return pcrs
}

func exists(i int, arr []int) bool {
	for _, elem := range arr {
		if elem == i {
			return true
		}
	}
	return false
}
