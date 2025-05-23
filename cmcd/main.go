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
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "cmcd")
)

func main() {

	c, err := GetConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Infof("Running cmc %v", cmc.GetVersion())

	cmc, err := cmc.NewCmc(&c.Config)
	if err != nil {
		log.Fatalf("Failed to init CMC: %v", err)
	}

	server, ok := servers[strings.ToLower(c.Api)]
	if !ok {
		log.Fatalf("API '%v' is not implemented", c.Api)
	}

	err = notifySystemd()
	if err != nil {
		log.Fatalf("Failed to notify systemd: %v", err)
	}

	err = server.Serve(c.CmcAddr, cmc)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

}
