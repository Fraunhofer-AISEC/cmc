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
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	log "github.com/sirupsen/logrus"
)

func (s *Server) handleVcekCertChain(w http.ResponseWriter, req *http.Request) {
	s.serveSnpCertChain(w, req, internal.VCEK)
}

func (s *Server) handleVlekCertChain(w http.ResponseWriter, req *http.Request) {
	s.serveSnpCertChain(w, req, internal.VLEK)
}

func (s *Server) serveSnpCertChain(w http.ResponseWriter, req *http.Request, akType internal.AkType) {
	codeName := req.PathValue("codeName")
	log.Debugf("Received %v cert_chain request for %q from %v", akType, codeName, req.RemoteAddr)

	ca, err := s.snpEndorser.GetSnpCa(codeName, akType)
	if err != nil {
		writeProxyError(w, "failed to get SNP %v CA chain for %q: %v", akType, codeName, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(internal.WriteCertsPemBlob(ca)); err != nil {
		log.Warnf("failed to write SNP CA response: %v", err)
	}
}

func (s *Server) handleVcek(w http.ResponseWriter, req *http.Request) {
	codeName := req.PathValue("codeName")
	chipIdHex := req.PathValue("chipId")

	log.Debugf("Received /vcek request for %q chip %v from %v", codeName, chipIdHex, req.RemoteAddr)

	chipId, err := hex.DecodeString(chipIdHex)
	if err != nil {
		writeBadRequest(w, "invalid chipId hex: %v", err)
		return
	}

	tcb, err := parseSnpTcbFromQuery(codeName, req.URL.Query())
	if err != nil {
		writeBadRequest(w, "%v", err)
		return
	}

	vcek, err := s.snpEndorser.GetSnpVcek(codeName, chipId, tcb)
	if err != nil {
		writeProxyError(w, "failed to get VCEK for %q chip %v tcb %x: %v", codeName, chipIdHex, tcb, err)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-cert")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(vcek.Raw); err != nil {
		log.Warnf("failed to write VCEK response: %v", err)
	}
}

func parseSnpTcbFromQuery(codeName string, query map[string][]string) (uint64, error) {
	bl, err := parseTcbField(query, "blSPL")
	if err != nil {
		return 0, err
	}
	tee, err := parseTcbField(query, "teeSPL")
	if err != nil {
		return 0, err
	}
	snp, err := parseTcbField(query, "snpSPL")
	if err != nil {
		return 0, err
	}
	ucode, err := parseTcbField(query, "ucodeSPL")
	if err != nil {
		return 0, err
	}
	tcb := ar.SnpTcb{Bl: bl, Tee: tee, Snp: snp, Ucode: ucode}
	if codeName == "Turin" {
		fmc, err := parseTcbField(query, "fmcSPL")
		if err != nil {
			return 0, err
		}
		tcb.Fmc = fmc
	}
	return ar.PackSnpTcb(codeName, tcb), nil
}

func parseTcbField(query map[string][]string, name string) (uint8, error) {
	values, ok := query[name]
	if !ok || len(values) == 0 {
		return 0, fmt.Errorf("missing query parameter %v", name)
	}
	v, err := strconv.ParseUint(values[0], 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid %v %q: %w", name, values[0], err)
	}
	return uint8(v), nil
}

func writeBadRequest(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warnf("%v", msg)
	http.Error(w, msg, http.StatusBadRequest)
}

func writeProxyError(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warnf("%v", msg)
	http.Error(w, msg, http.StatusBadGateway)
}
