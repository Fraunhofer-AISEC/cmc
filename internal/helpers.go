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

package internal

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "internal")

func FileExists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	}
	return false
}

func Contains(elem string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(s, elem) {
			return true
		}
	}
	return false
}

func FlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// Tests if the address is a network address in the form ip:port. In this
// case, returns "tcp" to be used as the transport layer, otherwise assumes
// that the address is a unix domain socket
func GetNetworkAndAddr(addr string) (string, string, error) {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return "tcp", addr, nil
	} else {
		a, err := filepath.Abs(addr)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse address '%v': %w", addr, err)
		}
		return "unix", a, nil
	}
}
