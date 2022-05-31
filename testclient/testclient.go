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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
)

// Mode defines the mode the testclient should run
type Mode int

const (
	// Generate an attestation report (Mode)
	Generate = 0
	// Verify an attestatoin report (Mode)
	Verify = 1
	// Create a TLS connection with an exemplary connector = server (Mode)
	TLSConn = 2
)

/* Creates TLS connection between this client and a server and performs a remote
 * attestation of the server before exchanging few a exemplary messages with it
 */
func testTLSConn(connectoraddress, rootCACertFile string, mTLS bool, port string, policies []byte) {
	var timeout = 10 * time.Second
	var conf *tls.Config

	// get root CA cert
	rootCA, err := ioutil.ReadFile(rootCACertFile)
	if err != nil {
		log.Error(err)
		log.Fatal("[Testclient] Could not find root CA cert file")
	}

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(rootCA)
	if !success {
		log.Fatal("[Testclient] Could not add cert to root CAs")
	}

	if mTLS {
		// Load own certificate
		var cert tls.Certificate
		cert, err = atls.GetCert(atls.WithCmcPort(port))
		if err != nil {
			log.Fatalf("[Testclient] failed to get TLS Certificate: %v", err)
		}
		// Create TLS config with root CA and own certificate
		conf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		}
	} else {
		// Create TLS config with root CA only
		conf = &tls.Config{
			RootCAs: roots,
		}
	}

	conn, err := atls.Dial("tcp", connectoraddress, conf, atls.WithCmcPort(port), atls.WithCmcCa(rootCA), atls.WithCmcPolicies(policies))
	if err != nil {
		log.Fatalf("[Testclient] failed to dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	// write sth
	_, err = conn.Write([]byte("hello\n"))
	if err != nil {
		log.Fatalf("[Testclient] failed to write: %v", err)
	}
	// read sth
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("[Testclient] failed to read. %v", err)
	}
	log.Info("[Testclient] received: " + string(buf[:n]))
}

func generate(client ci.CMCServiceClient, ctx context.Context, reportFile, nonceFile string) {
	// Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	request := ci.AttestationRequest{
		Nonce: nonce,
	}
	response, err := client.Attest(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Attest Call failed: %v", err)
	}
	if response.GetStatus() != ci.Status_OK {
		log.Fatalf("Failed to generate attestation report. Status %v", response.GetStatus())
	}

	// Save the Attestation Report for the verifier
	ioutil.WriteFile(reportFile, response.GetAttestationReport(), 0644)
	// Save the nonce for the verifier
	ioutil.WriteFile(nonceFile, nonce, 0644)

	fmt.Println("Wrote file ", reportFile)
}

func verify(client ci.CMCServiceClient, ctx context.Context, reportFile, resultFile, nonceFile, caFile string, policies []byte) {
	// Read the attestation report, CA and the nonce previously stored
	data, err := ioutil.ReadFile(reportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", reportFile, err)
	}

	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", caFile, err)
	}

	nonce, err := ioutil.ReadFile(nonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	request := ci.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                ca,
		Policies:          policies,
	}

	response, err := client.Verify(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Verify Call failed: %v", err)
	}
	if response.GetStatus() != ci.Status_OK {
		log.Warnf("Failed to verify attestation report. Status %v", response.GetStatus())
	}

	var out bytes.Buffer
	json.Indent(&out, response.GetVerificationResult(), "", "    ")

	// Save the Attestation Result
	ioutil.WriteFile(resultFile, out.Bytes(), 0644)
	fmt.Println("Wrote file ", resultFile)
}

func main() {
	log.SetLevel(log.TraceLevel)

	parsedMode := flag.String("mode", "generate", "[generate | verify | tlsconn ]")
	port := flag.String("port", "9955", "TCP Port to connect to the CMC daemon gRPC interface")
	reportFile := flag.String("report", "attestation-report.json", "Output file for the attestation report")
	resultFile := flag.String("result", "attestation-result.json", "Output file for the attestation result")
	nonceFile := flag.String("nonce", "nonce", "Output file for the nonce")
	connectoraddress := flag.String("connector", "0.0.0.0:443", "ip:port to connect to the test connector")
	rootCACertFile := flag.String("rootcacertfile", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	mTLS := flag.Bool("mTLS", false, "Performs mutual TLS with remote attestation on both sides. Only in mode tlsconn")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	flag.Parse()

	var mode Mode
	if strings.EqualFold(*parsedMode, "generate") {
		mode = Generate
	} else if strings.EqualFold(*parsedMode, "verify") {
		mode = Verify
	} else if strings.EqualFold(*parsedMode, "tlsconn") {
		mode = TLSConn
	} else {
		log.Fatal("Wrong mode. Possible [Generate | Verify | TLSConn]")
	}

	// Add optional policies if present
	var policies []byte = nil
	var err error
	if *policiesFile != "" {
		log.Debug("Policies specified. Adding them to verification request")
		policies, err = ioutil.ReadFile(*policiesFile)
		if err != nil {
			log.Fatalf("Failed to read policies file: %v", err)
		}
	} else {
		log.Debug("No policies specified. Verifying with default parameters")
	}

	addr := fmt.Sprintf("localhost:%v", *port)
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()

	client := ci.NewCMCServiceClient(conn)

	timeoutSec := 20
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	if mode == Generate {
		generate(client, ctx, *reportFile, *nonceFile)
	} else if mode == Verify {
		verify(client, ctx, *reportFile, *resultFile, *nonceFile, *rootCACertFile, policies)
	} else if mode == TLSConn {
		testTLSConn(*connectoraddress, *rootCACertFile, *mTLS, *port, policies)
	} else {
		log.Println("Unknown mode")
	}
}
