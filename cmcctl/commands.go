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

func generateCmd(c *config) {
	c.api.generate(c)
}

func verifyCmd(c *config) {
	c.api.verify(c)
}

func dialCmd(c *config) {
	c.api.dial(c)
}

func listenCmd(c *config) {
	c.api.listen(c)
}

func requestCmd(c *config) {
	c.api.request(c)
}

func serveCmd(c *config) {
	c.api.serve(c)
}

func updateMetadataCmd(c *config) {
	c.api.updateMetadata(c)
}

func updateCertsCmd(c *config) {
	c.api.updateCerts(c)
}

func tokenCmd(c *config) {
	err := createToken(c)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}
}

func provisionCmd(c *config) {
	err := retrieveProvisioningData(c)
	if err != nil {
		log.Fatalf("Failed to get provisioning data: %v", err)
	}
}
