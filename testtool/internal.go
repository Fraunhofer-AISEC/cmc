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
import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// Creates TLS connection between this client and a server and performs a remote
// attestation of the server before exchanging few a exemplary messages with it
func dialInternalAddr(c *config, api atls.CmcApiSelect, addr string, tlsConf *tls.Config, cmc *cmc.Cmc) error {
	verificationResult := new(ar.VerificationResult)

	conn, err := atls.Dial("tcp", addr, tlsConf,
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcCa(c.ca),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(api),
		atls.WithMtls(c.Mtls),
		atls.WithCmcNetwork(c.Network),
		atls.WithResult(verificationResult),
		atls.WithCmc(cmc))
	if err != nil {
		var attestedErr atls.AttestedError
		if errors.As(err, &attestedErr) {
			arresult := attestedErr.GetVerificationResult()
			result, err := json.Marshal(arresult)
			if err != nil {
				return fmt.Errorf("internal error: failed to marshal verification result: %v",
					err)
			}
			r, err := strconv.Unquote(string(result))
			if err != nil {
				r = string(result)
			}

			// Publish the attestation result if publishing address was specified
			err = publishResult(c.Publish, &arresult)
			if err != nil {
				log.Warnf("failed to publish result: %v", err)
			}

			return fmt.Errorf(
				"verification Result: %v. Cannot establish connection: remote attestation failed",
				r)
		}
		return fmt.Errorf("failed to dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeoutSec * time.Second))

	// Publish the attestation result if publishing address was specified
	err = publishResult(c.Publish, verificationResult)
	if err != nil {
		log.Warnf("failed to publish result: %v", err)
	}

	// Testing: write a hello string
	msg := "hello\n"
	log.Infof("Sending to peer: %v", msg)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("failed to write: %v", err)
	}

	// Testing: read the answer from the server and print
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read. %v", err)
	}
	log.Infof("Received from peer: %v", string(buf[:n-1]))

	return nil
}

// Wrapper for dialInternalAddr
func dialInternal(c *config, api atls.CmcApiSelect, cmc *cmc.Cmc) {
	var tlsConf *tls.Config

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(c.ca)
	if !success {
		log.Fatal("Could not add cert to root CAs")
	}

	if c.Mtls {
		// Load own certificate
		var cert tls.Certificate
		cert, err := atls.GetCert(
			atls.WithCmcAddr(c.CmcAddr),
			atls.WithCmcApi(api),
			atls.WithCmcNetwork(c.Network),
			atls.WithCmc(cmc))
		if err != nil {
			log.Fatalf("failed to get TLS Certificate: %v", err)
		}
		// Create TLS config with root CA and own certificate
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		}
	} else {
		// Create TLS config with root CA only
		tlsConf = &tls.Config{
			RootCAs:       roots,
			Renegotiation: tls.RenegotiateNever,
		}
	}

	internal.PrintTlsConfig(tlsConf, c.ca)

	testTime := time.Unix(0, 0)

	// Check if interval is non-negative
	if testTime.Before(testTime.Add(c.interval)) {
		ticker := time.NewTicker(c.interval)

		log.Infof("Starting monitoring with interval %v", c.interval)

		for {
			<-ticker.C
			for _, addr := range c.Addr {
				err := dialInternalAddr(c, api, addr, tlsConf, cmc)
				if err != nil {
					log.Warnf(err.Error())
				}
			}
		}
	} else {
		for _, addr := range c.Addr {
			err := dialInternalAddr(c, api, addr, tlsConf, cmc)
			if err != nil {
				log.Warnf(err.Error())
			}
		}
	}
}

func listenInternal(c *config, api atls.CmcApiSelect, cmc *cmc.Cmc) {
	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(c.ca)
	if !success {
		log.Fatal("Could not add cert to root CAs")
	}

	// Load certificate
	cert, err := atls.GetCert(
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcApi(api),
		atls.WithCmcNetwork(c.Network),
		atls.WithCmc(cmc))
	if err != nil {
		log.Fatalf("failed to get TLS Certificate: %v", err)
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
		ClientCAs:     roots,
		Renegotiation: tls.RenegotiateNever,
	}

	internal.PrintTlsConfig(tlsConf, c.ca)

	verificationResult := new(ar.VerificationResult)

	addr := ""
	if len(c.Addr) > 0 {
		addr = c.Addr[0]
	}

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", addr, tlsConf,
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcCa(c.ca),
		atls.WithCmcPolicies(c.policies),
		atls.WithCmcApi(api),
		atls.WithMtls(c.Mtls),
		atls.WithCmcNetwork(c.Network),
		atls.WithResult(verificationResult),
		atls.WithCmc(cmc))
	if err != nil {
		log.Fatalf("Failed to listen for connections: %v", err)
	}
	defer ln.Close()

	for {
		log.Infof("serving under %v", addr)
		// Finish TLS connection establishment with Remote Attestation
		conn, err := ln.Accept()
		if err != nil {
			var attestedErr atls.AttestedError
			if errors.As(err, &attestedErr) {
				arresult := attestedErr.GetVerificationResult()
				result, err := json.Marshal(arresult)
				if err != nil {
					log.Errorf("Internal error: failed to marshal verification result: %v", err)
				} else {
					r, err := strconv.Unquote(string(result))
					if err != nil {
						r = string(result)
					}

					// Publish the attestation result if publishing address was specified
					err = publishResult(c.Publish, &arresult)
					if err != nil {
						log.Warnf("failed to publish result: %v", err)
					}

					log.Errorf("Verification Result: %v\n"+
						"Cannot establish connection: Remote attestation Failed.", r)
				}
			} else {
				log.Errorf("Failed to establish connection: %v", err)
			}
			continue
		}

		// Handle established connections
		go handleConnection(conn)

		if c.Mtls {
			// Publish the attestation result if publishing address was specified
			err = publishResult(c.Publish, verificationResult)
			if err != nil {
				log.Warnf("failed to publish result: %v", err)
			}
		}
	}
}

func getCaCertsInternal(c *config) {
	addr := ""
	if len(c.Addr) > 0 {
		addr = c.Addr[0]
	}

	log.Info("Retrieving CA certs")
	client := est.NewClient(nil)
	certs, err := client.CaCerts(addr)
	if err != nil {
		log.Fatalf("Failed to retrieve certificates: %v", err)
	}
	log.Debug("Received certs:")
	for _, c := range certs {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	// Store CA certificate
	err = os.WriteFile(c.CaFile, internal.WriteCertPem(certs[len(certs)-1]), 0644)
	if err != nil {
		log.Fatalf("Failed to store CA certificate: %v", err)
	}
}

// Simply acts as an echo server and returns the received string
func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	msg, err := r.ReadString('\n')
	if err != nil {
		log.Errorf("Failed to read: %v", err)
	}
	log.Infof("Received from peer: %v", msg)

	log.Infof("Echoing: %v", msg)
	_, err = conn.Write([]byte(msg + "\n"))
	if err != nil {
		log.Errorf("Failed to write: %v", err)
	}
}

func publishResult(addr string, result *ar.VerificationResult) error {
	data, err := json.Marshal(*result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	return publish(addr, data)
}

func publish(addr string, result []byte) error {

	if addr == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewBuffer(result))
	if err != nil {
		return fmt.Errorf("failed to create new http request with context: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http post request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 201 {
		return fmt.Errorf("failed to publish result: server responded with %v: %v",
			resp.Status, string(data))
	}

	log.Tracef("Successfully published result: server responded with %v", resp.Status)

	return nil
}

func saveResult(file, addr string, result []byte) error {

	// Convert to human readable
	var out bytes.Buffer
	json.Indent(&out, result, "", "    ")

	// Save the Attestation Result to file
	if file != "" {
		os.WriteFile(file, out.Bytes(), 0644)
		fmt.Println("Wrote file ", file)
	} else {
		log.Debug("No config file specified: will not save attestation report")
	}

	// Publish the attestation result if publishing address was specified
	if addr != "" {
		err := publish(addr, result)
		if err != nil {
			log.Warnf("failed to publish result: %v", err)
		}
		log.Debug("Published attestation report")
	} else {
		log.Debug("No publish address specified: will not publish attestation report")
	}

	return nil
}
