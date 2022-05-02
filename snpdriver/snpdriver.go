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

package tpmdriver

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
	"encoding/hex"
	"encoding/pem"
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

func NewSnpDriver( /* TODO Config */ ) Snp {
	snp := Snp{} // TODO config

	ca, err := getCerts(milanUrl, PEM)
	if err != nil {
		return nil, fmt.Errorf("Failed to get SNP certificate chain: %v", err)
	}
	if len(ca) != 2 {
		return nil, fmt.Errorf("Failed to get SNP certificate chain. Expected 2 certificates, got %v", len(ca))
	}

	// The leaf certificate (VCEK) will be fetched with the attestation report
	snp.certChain = ar.CertChain{
		Intermediates: [][]byte{encodeCertPem(ca[0])},
		Ca:            encodeCertPem(ca[1]),
	}

	return snp
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (snp Snp) Measure(mp ar.MeasurementParams) (ar.Measurement, error) {

	snpParams, ok := mp.(ar.SnpParams)
	if !ok {
		return ar.SnpMeasurement{}, fmt.Errorf("Failed to retrieve SNP params - invalid type")
	}

	data, err := GetSnpMeasurement(snpParams.Nonce)
	if err != nil {
		return ar.SnpMeasurement{}, fmt.Errorf("Failed to get SNP Measurement: %v", err)
	}

	// TODO see if it is possible to do this in NewSnpDriver to avoid network interaction
	// on every attestation or only do it once
	s, err := ar.DecodeSnpReport(data)
	if err != nil {
		return ar.SnpMeasurement{}, fmt.Errorf("Failed to decode SNP report: %v", err)
	}
	ChipId := hex.EncodeToString(s.ChipId[:])
	tcbInfo := fmt.Sprintf("?blSPL=%v&teeSPL=%v&snpSPL=%v&ucodeSPL=%v",
		s.CurrentTcb&0xFF,
		(s.CurrentTcb>>8)&0xFF,
		(s.CurrentTcb>>48)&0xFF,
		(s.CurrentTcb>>56)&0xFF)
	vcek, err := getCerts(vcekUrlPrefix+ChipId+tcbInfo, DER)
	if err != nil {
		return nil, fmt.Errorf("Failed to get VCEK certificate: %v", err)
	}
	if len(vcek) != 1 {
		return nil, fmt.Errorf("Failed to get VCEK certificate. Expected 1 certificate, got %v", len(vcek))
	}
	snp.certChain.Leaf = encodeCertPem(vcek[0])

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
		return nil, fmt.Errorf("User Data must be at most 64 bytes")
	}

	log.Tracef("Generating SNP attestation report with nonce: %v", hex.EncodeToString(nonce))

	buf := make([]byte, 4000)
	cBuf := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	cLen := C.size_t(4000)
	cUserData := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	cUserDataLen := C.size_t(len(nonce))

	cRes, err := C.snp_dump_ar(cBuf, cLen, cUserData, cUserDataLen)
	if err != nil {
		return nil, fmt.Errorf("Error calling C.snp_dump_ar: %v", err)
	}

	res := int(cRes)
	if res != 0 {
		return nil, fmt.Errorf("C.snp_dump_ar returned: %v", err)
	}

	log.Tracef("Generated SNP attestation report: %v", hex.EncodeToString(buf))

	return buf, nil
}

func encodeCertPem(cert *x509.Certificate) []byte {
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return tmp.Bytes()
}

func getCerts(url string, format certFormat) ([]*x509.Certificate, error) {

	log.Tracef("Requesting Cert from %v", url)

	resp, err := http.Get(url)

	if err != nil {
		return nil, fmt.Errorf("Error HTTP GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP Response Status: %v (%v)", resp.StatusCode, resp.Status)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read HTTP body: %v", err)
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
		return nil, fmt.Errorf("Internal error: Unknown certificate format %v", format)
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse x509 Certificate: %v", err)
	}
	return certs, nil
}
