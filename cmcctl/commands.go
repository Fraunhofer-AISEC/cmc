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

func generateCmd(c *config) error {
	return c.api.generate(c)
}

func verifyCmd(c *config) error {
	return c.api.verify(c)
}

func dialCmd(c *config) error {
	return dial(c)
}

func listenCmd(c *config) error {
	return listen(c)
}

func requestCmd(c *config) error {
	return request(c)
}

func serveCmd(c *config) error {
	return serve(c)
}

func updateMetadataCmd(c *config) error {
	return c.api.updateMetadata(c)
}

func updateCertsCmd(c *config) error {
	return c.api.updateCerts(c)
}

func tokenCmd(c *config) error {
	return createToken(c)
}

func provisionCmd(c *config) error {
	return retrieveProvisioningData(c)
}
