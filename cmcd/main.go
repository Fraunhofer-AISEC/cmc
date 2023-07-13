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

import (
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

func main() {

	log.Infof("Starting cmcd %v", getVersion())

	c, err := getConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cmc, err := cmc.NewCmc(c)
	if err != nil {
		log.Fatalf("Failed to init CMC: %v", err)
	}

	server, ok := servers[strings.ToLower(c.Api)]
	if !ok {
		log.Fatalf("API '%v' is not implemented", c.Api)
	}

	err = server.Serve(c.Addr, cmc)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

}
