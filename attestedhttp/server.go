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

package attestedhttp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

// Wrapper for http.Server
type Server struct {
	*http.Server

	// Additional aTLS parameters
	Attest        atls.AttestSelect
	MutualTls     bool
	CmcAddr       string
	CmcApi        atls.CmcApiSelect
	ApiSerializer ar.Serializer
	Cmc           *cmc.Cmc
	CmcPolicies   []byte
	IdentityCas   []*x509.Certificate
	MetadataCas   []*x509.Certificate
	ResultCb      func(result *ar.VerificationResult)
}

func (s *Server) ListenAndServe() error {

	if s.Server.TLSConfig == nil {
		return errors.New("failed to listen: no TLS config provided")
	}

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", s.Server.Addr, s.Server.TLSConfig,
		atls.WithCmcAddr(s.CmcAddr),
		atls.WithCmcPolicies(s.CmcPolicies),
		atls.WithCmcApi(s.CmcApi),
		atls.WithIdentityCas(s.IdentityCas),
		atls.WithMetadataCas(s.MetadataCas),
		atls.WithApiSerializer(s.ApiSerializer),
		atls.WithMtls(s.MutualTls),
		atls.WithAttest(s.Attest),
		atls.WithResultCb(s.ResultCb),
		atls.WithCmc(s.Cmc))
	if err != nil {
		log.Fatalf("Failed to listen for connections: %v", err)
	}
	defer ln.Close()

	log.Infof("Serving HTTPS under %v", s.Server.Addr)

	err = s.Server.Serve(ln)
	if err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	log.Info("Finished serving HTTPS")

	return nil
}
