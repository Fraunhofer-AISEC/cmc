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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"encoding/json"
	"flag"

	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	pc "github.com/Fraunhofer-AISEC/cmc/provclient"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/fsnotify/fsnotify"
)

type config struct {
	Port          int    `json:"port"`
	ServerAddr    string `json:"provServerAddr"`
	ServerPath    string `json:"serverPath"`
	LocalPath     string `json:"localPath"`
	FetchMetadata bool   `json:"fetchMetadata"`
	UseIma        bool   `json:"useIma"`
	ImaPcr        int32  `json:"imaPcr"`
	// Key config: RSA2048 RSA4096 EC256 EC384 EC521
	KeyConfig string `json:"keyConfig,omitempty"` // Default defined below during parsing

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

func loadConfig(configFile string) (*config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read cmcd config file %v: %v", configFile, err)
	}
	// Default configuration
	c := &config{
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

func watchFileChanges(watcher *fsnotify.Watcher, config *ServerConfig, path string) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			log.Tracef("file system event: %v", event)
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Tracef("modified file: %v", event.Name)
				metadata, _, pcrs, err := loadMetadata(path)
				if err != nil {
					return
				}
				config.Metadata = metadata
				config.Pcrs = pcrs
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}
}

func main() {

	log.SetFormatter(&log.TextFormatter{
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000",
	})

	log.SetLevel(log.TraceLevel)

	log.Info("Starting CMC")

	configFile := flag.String("config", "", "configuration file")
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

	// Load the cmcd configuration from the cmdline specified configuration file
	c, err := loadConfig(*configFile)
	if err != nil {
		log.Errorf("Failed to load config: %v", err)
		return
	}

	// If configured, fetch device metadata from provisioning server and store it
	// on the local path specified in the cmcd configuration, afterwards load it
	if c.FetchMetadata {
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

	// Check if the TPM is provisioned. If provisioned, load the AK and TLS key.
	// Otherwise perform credential activation with provisioning server and then load the keys
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

	serverConfig := &ServerConfig{
		Metadata: metadata,
		Certs:    certs,
		Pcrs:     pcrs,
		Roles:    roles,
		Tpm:      &tpmdriver.Tpm{},
	}

	// Watch file system for metadata file changes
	log.Tracef("Registering watcher for file changes in %v", c.LocalPath)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("Failed to create watcher for file changes: %v", err)
		return
	}
	defer watcher.Close()
	go watchFileChanges(watcher, serverConfig, c.LocalPath)
	err = watcher.Add(c.LocalPath)
	if err != nil {
		log.Errorf("Failed to add watcher for file changes in %v", c.LocalPath)
		return
	}

	server := NewServer(serverConfig)

	addr := "127.0.0.1:" + strconv.Itoa(c.Port)
	err = Serve(addr, &server)
	if err != nil {
		log.Error(err)
		return
	}
}
