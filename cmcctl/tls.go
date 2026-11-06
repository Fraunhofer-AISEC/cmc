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
func dial(c *Config) error {

	tlsConf, err := createClientTlsConf(c)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Wait for pending publishing before the command exits
	var wg sync.WaitGroup
	defer wg.Wait()

	conn, err := atls.Dial("tcp", c.Atls.Addr, tlsConf,
		atls.WithCmcAddr(c.cmcAddr),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(c.apiName),
		atls.WithSerializer(c.serializer),
		atls.WithMtls(c.Atls.Mtls),
		atls.WithAttest(c.attest),
		atls.WithResultCb(func(result *ar.AttestationResult) {
			// Publish asynchronously
			if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Server {
				wg.Add(1)
				go pub.PublishAsync(c.Publish.Results, c.Publish.Ocsf, c.Publish.Network, c.publishToken, c.Publish.Result, result, &wg,
					c.rootCas, c.Trust.AllowSystemCerts, c.publishClientCert)
			}
		}),
		atls.WithLibApiCmcConfig(&c.Cmc, c.rootCas, c.Trust.AllowSystemCerts))
	if err != nil {
		return fmt.Errorf("failed to dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeoutSec * time.Second))

	if len(c.Request.Data) == 0 {
		log.Info("No data to send via atls configured. Finished")
		return nil
	}

	// Send configured data
	log.Infof("Sending to peer: %q", c.Request.Data)
	_, err = conn.Write([]byte(c.Request.Data))
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

func listen(c *Config) error {

	// Create TLS config
	tlsConf, err := createServerTlsConf(c)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", c.Atls.Addr, tlsConf,
		atls.WithCmcAddr(c.cmcAddr),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(c.apiName),
		atls.WithSerializer(c.serializer),
		atls.WithMtls(c.Atls.Mtls),
		atls.WithAttest(c.attest),
		atls.WithResultCb(func(result *ar.AttestationResult) {
			if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Client {
				// Publish the attestation result if publishing address was specified
				// and result is not empty
				go pub.Publish(c.Publish.Results, c.Publish.Ocsf, c.Publish.Network, c.publishToken, c.Publish.Result, result,
					c.rootCas, c.Trust.AllowSystemCerts, c.publishClientCert)
			}
		}),
		atls.WithLibApiCmcConfig(&c.Cmc, c.rootCas, c.Trust.AllowSystemCerts))
	if err != nil {
		return fmt.Errorf("failed to listen for connections: %w", err)
	}
	defer ln.Close()

	log.Infof("Serving under %v", c.Atls.Addr)

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

// useAttestationOnlyTrust returns whether the validation of the peer's certificate chain shall be
// replaced by remote attestation of the peer. Authorization is then enforced through the
// attestation instead of through the certificate chain.
func useAttestationOnlyTrust(c *Config, peer atls.AttestSelect) (bool, error) {
	if !c.Atls.AttestationOnlyTrust {
		return false, nil
	}
	if c.attest != peer && c.attest != atls.Attest_Mutual {
		return false, fmt.Errorf(
			"attestation-only trust requires the attestation of the peer, but attestation mode is %q",
			c.Atls.Attest)
	}
	return true, nil
}

func createClientTlsConf(c *Config) (*tls.Config, error) {

	attestationOnly, err := useAttestationOnlyTrust(c, atls.Attest_Server)
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		Renegotiation: tls.RenegotiateNever,
	}

	if attestationOnly {
		// Trust the server based on its attestation report only, e.g. if it uses a self-signed
		// certificate
		log.Debug("Skipping server certificate chain validation: server is attested")
		tlsConf.InsecureSkipVerify = true
	} else {
		rootpool, err := internal.CreateCertPool(c.rootCas, c.Trust.AllowSystemCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert pool: %w", err)
		}
		tlsConf.RootCAs = rootpool
	}

	if c.Atls.Mtls {
		// Retrieve cert from CMC for mTLS
		cert, err := getTlsCert(c)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS cert: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	internal.PrintTlsConfig(tlsConf, c.rootCas)

	return tlsConf, nil
}

func createServerTlsConf(c *Config) (*tls.Config, error) {

	// The client certificate is only validated if the client authenticates via mTLS
	attestationOnly := false
	if c.Atls.Mtls {
		var err error
		attestationOnly, err = useAttestationOnlyTrust(c, atls.Attest_Client)
		if err != nil {
			return nil, err
		}
	}

	// Load certificate
	cert, err := getTlsCert(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS certificate: %w", err)
	}

	tlsConf := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		Renegotiation: tls.RenegotiateNever,
	}

	if attestationOnly {
		// Trust the client based on its attestation report only, e.g. if it uses a self-signed
		// certificate
		log.Debug("Skipping client certificate chain validation: client is attested")
		tlsConf.ClientAuth = tls.RequireAnyClientCert
	} else {
		rootpool, err := internal.CreateCertPool(c.rootCas, c.Trust.AllowSystemCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert pool: %w", err)
		}
		tlsConf.ClientCAs = rootpool
		if c.Atls.Mtls {
			// Mandate client authentication
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			// Make client authentication optional
			tlsConf.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	internal.PrintTlsConfig(tlsConf, c.rootCas)

	return tlsConf, nil
}

func getTlsCert(c *Config) (tls.Certificate, error) {

	fqdn, err := internal.Fqdn()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to retrieve fqdn: %w", err)
	}

	// Use configured CN, DNS names and IP addresses for SANs if specified, otherwise use FQDN
	cn := fqdn
	if c.Identity.Cn != "" {
		cn = c.Identity.Cn
	}
	dnsNames := []string{fqdn}
	if len(c.Identity.DnsNames) > 0 {
		dnsNames = c.Identity.DnsNames
	}

	log.Tracef("Fetching TLS %v %v certificate", c.Identity.KeyType, c.Identity.KeyConfig)

	return atls.GetOrCreateCert(&c.keyId, c.Identity.KeyId,
		atls.WithKeyConfig(api.TLSKeyConfig{
			Type:        c.Identity.KeyType,
			Alg:         c.Identity.KeyConfig,
			Cn:          cn,
			DNSNames:    dnsNames,
			IPAddresses: c.Identity.IpAddresses,
		}),
		atls.WithCmcAddr(c.cmcAddr),
		atls.WithCmcApi(c.apiName),
		atls.WithSerializer(c.serializer),
		atls.WithLibApiCmcConfig(&c.Cmc, c.rootCas, c.Trust.AllowSystemCerts))
}
