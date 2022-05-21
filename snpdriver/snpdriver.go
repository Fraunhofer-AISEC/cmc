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

package snpdriver

/*
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ioctl.h"
*/
import "C"
import (
	"bytes"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"net/http"
	"unsafe"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	log "github.com/sirupsen/logrus"
)

const (
	PEM = iota
	DER = iota
)

type certFormat int

var (
	vcekUrlPrefix = "https://kdsintf.amd.com/vcek/v1/Milan/"

	milanUrl = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
)

// Snp is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Snp struct {
	certChain ar.CertChain
}

type Config struct {
	Url string
}

type VcekRequest struct {
	ChipId [64]byte
	Tcb    uint64
}

type VcekResponse struct {
	Vcek []byte
}

func NewSnpDriver(c Config) (*Snp, error) {
	snp := &Snp{}

	ca, _, err := getCerts(milanUrl, PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP certificate chain: %w", err)
	}
	if len(ca) != 2 {
		return nil, fmt.Errorf("failed to get SNP certificate chain. Expected 2 certificates, got %v", len(ca))
	}

	// Fetch the VCEK. TODO as a workaround, we get the parameters through
	// fetching an initial attestation report and request the VCEK from the
	// Provisioning server. As soon as we can reliably get the correct TCB,
	// the host should provide the VCEK
	arRaw, err := GetSnpMeasurement(make([]byte, 64))
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP report: %w", err)
	}
	s, err := ar.DecodeSnpReport(arRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SNP report: %w", err)
	}
	req := VcekRequest{
		ChipId: s.ChipId,
		Tcb:    s.CurrentTcb,
	}
	resp, err := fetchVcek(c.Url+"vcek-retrieval/", req)
	if err != nil {
		return nil, fmt.Errorf("failed to get VCEK: %w", err)
	}

	snp.certChain = ar.CertChain{
		Leaf:          resp.Vcek,
		Intermediates: [][]byte{encodeCertPem(ca[0])},
		Ca:            encodeCertPem(ca[1]),
	}

	return snp, nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (snp Snp) Measure(nonce []byte) (ar.Measurement, error) {

	data, err := GetSnpMeasurement(nonce)
	if err != nil {
		return ar.SnpMeasurement{}, fmt.Errorf("failed to get SNP Measurement: %w", err)
	}

	measurement := ar.SnpMeasurement{
		Type:   "SNP Measurement",
		Report: data,
		Certs:  snp.certChain,
	}

	return measurement, nil
}

// GetSnpMeasurement retrieves the AMD SEV-SNP attestation report
// and returns it as a byte array
func GetSnpMeasurement(nonce []byte) ([]byte, error) {

	if len(nonce) > 64 {
		return nil, errors.New("user Data must be at most 64 bytes")
	}

	log.Tracef("Generating SNP attestation report with nonce: %v", hex.EncodeToString(nonce))

	buf := make([]byte, 4000)
	cBuf := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	cLen := C.size_t(4000)
	cUserData := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	cUserDataLen := C.size_t(len(nonce))

	cRes, err := C.snp_dump_ar(cBuf, cLen, cUserData, cUserDataLen)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SNP AR: %w", err)
	}

	res := int(cRes)
	if res != 0 {
		return nil, fmt.Errorf("failed to retrieve SNP AR. C.snp_dump_ar returned %v", res)
	}

	log.Tracef("Generated SNP attestation report: %v", hex.EncodeToString(buf))

	return buf, nil
}

func encodeCertPem(cert *x509.Certificate) []byte {
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return tmp.Bytes()
}

func getCerts(url string, format certFormat) ([]*x509.Certificate, int, error) {

	log.Tracef("Requesting Cert from %v", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("error HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP Response Status: %v (%v)", resp.StatusCode, resp.Status)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read HTTP body: %w", err)
	}

	var data []byte
	if format == PEM {
		rest := content
		var block *pem.Block
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			data = append(data, block.Bytes...)

		}
	} else if format == DER {
		data = content
	} else {
		return nil, resp.StatusCode, fmt.Errorf("internal error: Unknown certificate format %v", format)
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse x509 Certificate: %w", err)
	}
	return certs, resp.StatusCode, nil
}

func fetchVcek(url string, req VcekRequest) (VcekResponse, error) {
	var buf bytes.Buffer
	e := gob.NewEncoder(&buf)
	if err := e.Encode(req); err != nil {
		return VcekResponse{}, fmt.Errorf("failed to send request to server: %v", err)
	}

	log.Debugf("Sending CSR HTTP POST Request to %v", url)

	resp, err := http.Post(url, "retrieval/vcek", &buf)
	if err != nil {
		return VcekResponse{}, fmt.Errorf("error sending params - %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(resp.Body)
		log.Warn("Request failed: body: ", string(b))
		return VcekResponse{}, fmt.Errorf("request Failed: HTTP Server responded '%v'", resp.Status)
	}

	log.Debug("HTTP Response OK")

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return VcekResponse{}, fmt.Errorf("error sending params - %v", err)
	}

	var response VcekResponse
	d := gob.NewDecoder((bytes.NewBuffer(b)))
	d.Decode(&response)

	return response, nil
}
