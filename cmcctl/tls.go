// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

// Creates TLS connection between this client and a server and performs a remote
// attestation of the server before exchanging exemplary messages with it
func dial(c *config) error {

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
		atls.WithResultCb(func(result *ar.AttestationResult) {
			// Publish the attestation result asynchronously if publishing address was specified and
			// and attestation was performed
			if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Server {
				wg := new(sync.WaitGroup)
				wg.Add(1)
				defer wg.Wait()
				go pub.PublishAsync(c.PublishResults, c.PublishOcsf, c.PublishNetwork, c.publishToken, c.ResultFile, result, wg)
			}
		}),
		atls.WithLibApiCmcConfig(&c.Config))
	if err != nil {
		return fmt.Errorf("failed to dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeoutSec * time.Second))

	if len(c.Data) == 0 {
		log.Info("No data to send via atls configured. Finished")
		return nil
	}

	// Send configured data
	log.Infof("Sending to peer: %q", c.Data)
	_, err = conn.Write([]byte(c.Data))
	if err != nil {
		return fmt.Errorf("failed to write: %v", err)
	}

	// Receive answer from server
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read. %v", err)
	}
	log.Infof("Received from peer: %q", string(buf[:n]))

	return nil
}

func listen(c *config) error {

	rootpool, err := internal.CreateCertPool(c.rootCas, c.AllowSystemCerts)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	// Load certificate
	cert, err := getTlsCert(c)
	if err != nil {
		return fmt.Errorf("failed to get TLS Certificate: %w", err)
	}

	var clientAuth tls.ClientAuthType
	if c.Mtls {
		// Mandate client authentication
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		// Make client authentication optional
		clientAuth = tls.VerifyClientCertIfGiven
	}

	// Create TLS config
	tlsConf := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		ClientAuth:    clientAuth,
		ClientCAs:     rootpool,
		Renegotiation: tls.RenegotiateNever,
	}

	internal.PrintTlsConfig(tlsConf, c.rootCas)

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", c.Addr, tlsConf,
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(c.Api),
		atls.WithSerializer(c.serializer),
		atls.WithMtls(c.Mtls),
		atls.WithAttest(c.attest),
		atls.WithResultCb(func(result *ar.AttestationResult) {
			if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Client {
				// Publish the attestation result if publishing address was specified
				// and result is not empty
				go pub.Publish(c.PublishResults, c.PublishOcsf, c.PublishNetwork, c.publishToken, c.ResultFile, result)
			}
		}),
		atls.WithLibApiCmcConfig(&c.Config))
	if err != nil {
		return fmt.Errorf("failed to listen for connections: %w", err)
	}
	defer ln.Close()

	log.Infof("Serving under %v", *addr)

	for {
		// Accept connection and perform remote attestation
		conn, err := ln.Accept()
		if err != nil {
			log.Warnf("Failed to establish connection: %v", err)
			continue
		}

		// Handle established connections
		go handleConnection(conn)
	}
}

// Simply acts as an echo server and returns the received string
func handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Warnf("Read error: %v", err)
			}
			return
		}

		data := buf[:n]
		log.Infof("Received %q. Echoing...", string(data))

		_, err = conn.Write(data)
		if err != nil {
			log.Errorf("Write error: %v", err)
			return
		}
	}
}

func createClientTlsConf(c *config) (*tls.Config, error) {

	rootpool, err := internal.CreateCertPool(c.rootCas, c.AllowSystemCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert pool: %w", err)
	}

	if !c.Mtls {
		// Create TLS config with root CA only
		return &tls.Config{
			RootCAs:       rootpool,
			Renegotiation: tls.RenegotiateNever,
		}, nil
	}

	// Retrieve cert from CMC for mTLS
	cert, err := getTlsCert(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS cert: %w", err)
	}

	// Create TLS config with root CA and own certificate
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootpool,
	}

	internal.PrintTlsConfig(tlsConf, c.rootCas)

	return tlsConf, nil
}

func getTlsCert(c *config) (tls.Certificate, error) {
	// Check if there is already a key configured for this cmcctl instance
	if c.keyId != "" {
		cert, err := atls.GetCert(
			atls.WithKeyId(c.keyId),
			atls.WithCmcAddr(c.CmcAddr),
			atls.WithCmcApi(c.Api),
			atls.WithSerializer(c.serializer),
			atls.WithLibApiCmcConfig(&c.Config))
		if err == nil {
			log.Tracef("Found key with key id %s", c.keyId)
			return cert, nil
		} else {
			log.Warnf("Failed to retrieve certificate for key ID %v. Creating new key", c.keyId)
		}
	}

	fqdn, err := internal.Fqdn()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to retrieve fqdn: %w", err)
	}

	log.Tracef("Creating new TLS %v %v key and certificate", c.KeyType, c.KeyConfig)
	keyId, err := atls.CreateCert(
		atls.WithKeyId(c.keyId),
		atls.WithKeyConfig(api.TLSKeyConfig{
			Type:     c.KeyType,
			Alg:      c.KeyConfig,
			Cn:       fqdn,
			DNSNames: []string{fqdn},
		}),
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcApi(c.Api),
		atls.WithSerializer(c.serializer),
		atls.WithLibApiCmcConfig(&c.Config))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create TLS key and cert: %w", err)
	}
	c.keyId = keyId

	// Store key ID
	if c.KeyIdFile != "" {
		if err := os.MkdirAll(filepath.Dir(c.KeyIdFile), 0755); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to create key ID file directory: %w", err)
		}
		err := os.WriteFile(c.KeyIdFile, []byte(keyId), 0600)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to write key ID: %w", err)
		}
	}

	// Retrieve the newly created certificate
	cert, err := atls.GetCert(
		atls.WithKeyId(c.keyId),
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcApi(c.Api),
		atls.WithSerializer(c.serializer),
		atls.WithLibApiCmcConfig(&c.Config))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to retrieve certificate for key ID %v: %w", keyId, err)
	}

	// Return TLS config with root CA and own certificate
	return cert, nil

}
