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

	"google.golang.org/grpc"

	// local modules
	ci "cmcinterface"
	cl "connectorlibrary"

	log "github.com/sirupsen/logrus"
)

type Mode int

const (
	Generate = 0
	Verify   = 1
	TLSConn  = 2
)

func TestTLSConn(connectoraddress, rootCACertFile string) {
	var timeout = 10 * time.Second
	// get server cert
	servercert, err := ioutil.ReadFile(rootCACertFile)
	if err != nil {
		log.Error("[Testclient] Could find root CA cert file.")
		return
	}
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(servercert)
	if !success {
		log.Error("[Testclient] Could not add servercert to root CAs.")
		return
	}
	// Create TLS config with server as root CA
	conf := &tls.Config{
		//InsecureSkipVerify: true,
		RootCAs: roots,
	}
	conn, err := cl.Dial("tcp", connectoraddress, conf)
	if err != nil {
		log.Error("[Testclient] failed to dial server. \n", err)
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	// write sth
	_, err = conn.Write([]byte("hello\n"))
	if err != nil {
		log.Error("[Testclient] failed to write. \n", err)
		return
	}
	// read sth
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Error("[Testclient] failed to read. \n", err)
		return
	}
	log.Info("[Testclient] received: " + string(buf[:n]))
}

func main() {
	log.SetLevel(log.TraceLevel)

	parsedMode := flag.String("mode", "generate", "[generate | verify | tlsconn]")
	port := flag.String("port", "9955", "TCP Port to connect to the CMC daemon gRPC interface")
	connectoraddress := flag.String("connector", "localhost:4443", "ip:port to connect to the test connector")
	rootCACertFile := flag.String("rootcacertfile", "../../pki_and_signing/examples/demo_setup/pki/ca/ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	flag.Parse()

	var mode Mode
	if strings.ToLower(*parsedMode) == strings.ToLower("generate") {
		mode = Generate
	} else if strings.ToLower(*parsedMode) == strings.ToLower("verify") {
		mode = Verify
	} else if strings.ToLower(*parsedMode) == strings.ToLower("tlsconn") {
		mode = TLSConn
	} else {
		log.Fatal("Wrong mode. Possible [Generate | Verify | TLSConn]")
	}

	addr := fmt.Sprintf("localhost:%v", *port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()

	client := ci.NewCMCServiceClient(conn)

	timeoutSec := 10
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	if mode == Generate {

		// Generate random nonce
		nonce := make([]byte, 8)
		_, err = rand.Read(nonce)
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
		fileName := "attestation-report.json"
		ioutil.WriteFile(fileName, response.GetAttestationReport(), 0644)
		// Save the nonce for the verifier
		ioutil.WriteFile("nonce", nonce, 0644)

		fmt.Println("Wrote file ", fileName)

	} else if mode == Verify {
		// Read the attestation report and the nonce previously stored
		fileName := "attestation-report.json"
		data, err := ioutil.ReadFile(fileName)
		if err != nil {
			log.Fatalf("Failed to read file %v: %v", fileName, err)
		}

		var nonce []byte
		nonce, err = ioutil.ReadFile("nonce")
		if err != nil {
			log.Fatalf("Failed to read nonce: %v", err)
		}

		request := ci.VerificationRequest{
			Nonce:             nonce,
			AttestationReport: data,
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
		fileName = "attestation-result.json"
		ioutil.WriteFile(fileName, out.Bytes(), 0644)
		fmt.Println("Wrote file ", fileName)
	} else if mode == TLSConn {
		TestTLSConn(*connectoraddress, *rootCACertFile)
	} else {
		log.Println("Unknown mode")
	}
}
