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

// local modules

func generate(c *config) {
	c.api.generate(c)
}

func verify(c *config) {
	c.api.verify(c)
}

func measure(c *config) {
	c.api.measure(c)
}

func dial(c *config) {
	c.api.dial(c)
}

func listen(c *config) {
	c.api.listen(c)
}

func request(c *config) {
	c.api.request(c)
}

func serve(c *config) {
	c.api.serve(c)
}

func getCaCerts(c *config) {
	c.api.cacerts(c)
}

func iothub(c *config) {
	c.api.iothub(c)
}
