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

//go:build !nodefaults || socket || grpc

package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
)

// socketGroup is granted access to the unix socket if it exists
const socketGroup = "cmc"

// listen listens on a TCP address or unix domain socket as parsed by api.GetNetworkAndAddr.
// Unix domain sockets are restricted to their owner and socketGroup and removed on termination.
func listen(address string) (net.Listener, error) {

	network, addr := api.GetNetworkAndAddr(address)

	log.Infof("Waiting for requests on %v (%v)", addr, network)

	listener, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	if network == "unix" {
		if err := restrictSocket(addr); err != nil {
			listener.Close()
			return nil, err
		}

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			os.Remove(addr)
			os.Exit(1)
		}()
	}

	return listener, nil
}

// restrictSocket grants the members of socketGroup access to the unix socket
// at path. Without that group, only the owner can access the socket.
func restrictSocket(path string) error {

	mode := os.FileMode(0600)
	if g, err := user.LookupGroup(socketGroup); err != nil {
		log.Debugf("Group %v not found, restricting %v to its owner", socketGroup, path)
	} else if gid, err := strconv.Atoi(g.Gid); err != nil {
		return fmt.Errorf("invalid gid %v of group %v: %w", g.Gid, socketGroup, err)
	} else if err := os.Chown(path, -1, gid); err != nil {
		log.Warnf("Failed to grant group %v access to %v, restricting it to its owner: %v",
			socketGroup, path, err)
	} else {
		mode = 0660
	}

	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set permissions of %v: %w", path, err)
	}
	return nil
}

func Sign(mgr *keymgr.KeyMgr, keyId, hashAlg string, digest []byte) ([]byte, error) {

	key, err := mgr.GetKey(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	hash, err := internal.HashFromString(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	signature, err := key.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, err
}
