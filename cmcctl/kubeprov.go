// Copyright (c) 2026 Fraunhofer AISEC
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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type joinInfo struct {
	APIServer  string `json:"apiServer"`
	Token      string `json:"token"`
	CACertHash string `json:"caCertHash"`
}

func kubeprovServe(c *config) error {
	rootPool, err := internal.CreateCertPool(c.rootCas, c.AllowSystemCerts)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	cert, err := getTlsCert(c)
	if err != nil {
		return fmt.Errorf("failed to get TLS certificate: %w", err)
	}

	var clientAuth tls.ClientAuthType
	if c.Mtls {
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		clientAuth = tls.VerifyClientCertIfGiven
	}

	tlsConf := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		ClientAuth:    clientAuth,
		ClientCAs:     rootPool,
		Renegotiation: tls.RenegotiateNever,
	}

	internal.PrintTlsConfig(tlsConf, c.rootCas)

	ln, err := atls.Listen("tcp", c.Addr, tlsConf,
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(c.Api),
		atls.WithSerializer(c.serializer),
		atls.WithMtls(c.Mtls),
		atls.WithAttest(c.attest),
		atls.WithLibApiCmcConfig(&c.Config))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer ln.Close()

	log.Infof("Serving on %v", c.Addr)

	var wg sync.WaitGroup
	served := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Warnf("Failed to accept connection: %v", err)
			continue
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			kubeprovHandleConn(conn, c.KubeadmPath)
		}(conn)

		served++
		if c.KubeprovCount > 0 && served >= c.KubeprovCount {
			log.Infof("Served %d worker(s), waiting for handlers to finish", served)
			wg.Wait()
			log.Infof("All handlers finished, exiting")
			return nil
		}
	}
}

func kubeprovHandleConn(conn net.Conn, kubeadmPath string) {
	defer conn.Close()

	info, err := createJoinToken(kubeadmPath)
	if err != nil {
		log.Errorf("Failed to create join token: %v", err)
		return
	}

	data, err := json.Marshal(info)
	if err != nil {
		log.Errorf("Failed to marshal join info: %v", err)
		return
	}

	if err := atls.Write(data, conn); err != nil {
		log.Errorf("Failed to send join info: %v", err)
		return
	}

	log.Infof("Sent join info to %v (server: %v)", conn.RemoteAddr(), info.APIServer)
}

func createJoinToken(kubeadmPath string) (*joinInfo, error) {
	out, err := exec.Command(kubeadmPath, "token", "create", "--print-join-command").Output()
	if err != nil {
		return nil, fmt.Errorf("kubeadm token create failed: %w", err)
	}
	return parseJoinCommand(strings.TrimSpace(string(out)))
}

func parseJoinCommand(line string) (*joinInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 7 || fields[0] != "kubeadm" || fields[1] != "join" {
		return nil, fmt.Errorf("unexpected kubeadm output: %q", line)
	}

	info := &joinInfo{APIServer: fields[2]}
	for i := 3; i < len(fields)-1; i++ {
		switch fields[i] {
		case "--token":
			info.Token = fields[i+1]
		case "--discovery-token-ca-cert-hash":
			info.CACertHash = fields[i+1]
		}
	}

	if info.Token == "" || info.CACertHash == "" {
		return nil, fmt.Errorf("failed to parse token or hash from: %q", line)
	}
	return info, nil
}

func kubeprovJoin(c *config) error {
	tlsConf, err := createClientTlsConf(c)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	conn, err := atls.Dial("tcp", c.Addr, tlsConf,
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(c.Api),
		atls.WithSerializer(c.serializer),
		atls.WithMtls(c.Mtls),
		atls.WithAttest(c.attest),
		atls.WithLibApiCmcConfig(&c.Config))
	if err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}
	defer conn.Close()

	data, err := atls.Read(conn)
	if err != nil {
		return fmt.Errorf("failed to read join info: %w", err)
	}

	var info joinInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("failed to parse join info: %w", err)
	}

	log.Infof("Received join info: server=%v", info.APIServer)

	if c.KubeprovDryRun {
		fmt.Printf("apiServer: %s\ntoken: %s\ncaCertHash: %s\n",
			info.APIServer, info.Token, info.CACertHash)
		return nil
	}

	return execKubeadmJoin(c.KubeadmPath, &info)
}

func execKubeadmJoin(kubeadmPath string, info *joinInfo) error {
	log.Infof("Executing: %s join %s", kubeadmPath, info.APIServer)

	cmd := exec.Command(kubeadmPath, "join", info.APIServer,
		"--token", info.Token,
		"--discovery-token-ca-cert-hash", info.CACertHash)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubeadm join failed: %w", err)
	}
	return nil
}
