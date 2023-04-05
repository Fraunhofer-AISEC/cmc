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
	"path"
	"strings"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/est/client"
)

func main() {

	log.Infof("Starting cmcd %v", getVersion())

	c, err := getConfig()
	if err != nil {
		log.Errorf("failed to load config: %v", err)
		return
	}

	provConfig := &client.Config{
		FetchMetadata: c.FetchMetadata,
		StoreMetadata: true,
		LocalPath:     c.LocalPath,
		RemoteAddr:    c.MetadataAddr,
	}
	metadata, err := client.ProvisionMetadata(provConfig)
	if err != nil {
		log.Errorf("Failed to provision metadata: %v", err)
		return
	}

	// Create driver configuration
	driverConf := &ar.DriverConfig{
		StoragePath: path.Join(c.LocalPath, "internal"),
		ServerAddr:  c.ProvServerAddr,
		KeyConfig:   c.KeyConfig,
		Metadata:    metadata,
		UseIma:      c.UseIma,
		ImaPcr:      c.ImaPcr,
		Serializer:  c.serializer,
	}

	// Initialize drivers
	for _, m := range c.drivers {
		err = m.Init(driverConf)
		if err != nil {
			log.Errorf("Failed to initialize measurer: %v", err)
			return
		}
	}

	serverConfig := &ServerConfig{
		Metadata:           metadata,
		Drivers:            c.drivers,
		Serializer:         c.serializer,
		PolicyEngineSelect: c.policyEngineSelect,
		Network:            c.Network,
	}

	server, ok := servers[strings.ToLower(c.Api)]
	if !ok {
		log.Errorf("API '%v' is not implemented", c.Api)
		return
	}

	server.Serve(c.Addr, serverConfig)
}
