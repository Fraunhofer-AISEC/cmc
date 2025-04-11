// Copyright (c) 2025 Fraunhofer AISEC
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
	"fmt"
	"os"

	"github.com/coreos/go-systemd/daemon"
)

func notifySystemd() error {

	if _, ok := os.LookupEnv("NOTIFY_SOCKET"); !ok {
		log.Debugf("Not running under systemd, skipping notification")
		return nil
	}

	sent, err := daemon.SdNotify(false, daemon.SdNotifyReady)
	if err != nil {
		return fmt.Errorf("systemd notify returned error: %v", err)
	}
	if !sent {
		return fmt.Errorf("systemd notify returned false")
	}

	log.Debugf("Notified systemd: cmcd is ready")

	return nil
}
