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

// Package server implements the server side of the cmc node attestor. It verifies attestation
// reports with the embedded CMC verifier and maps the attestation result to the agent ID and
// selectors.
package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	na "github.com/Fraunhofer-AISEC/cmc/spire/nodeattestor"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

const defaultPolicyEngine = "js"

// Config is the HCL plugin configuration
type Config struct {
	// RootCas are the paths to the trusted root CA PEM files
	RootCas []string `hcl:"root_cas"`
	// Policies is the optional path to a CMC policy file
	Policies string `hcl:"policies"`
	// PolicyEngine is the engine evaluating Policies
	PolicyEngine string `hcl:"policy_engine"`
}

type config struct {
	trustDomain  spiffeid.TrustDomain
	rootCas      []*x509.Certificate
	policies     []byte
	policyEngine verifier.PolicyEngineSelect
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mtx    sync.RWMutex
	config *config
	logger hclog.Logger
}

func New() *Plugin {
	return &Plugin{logger: hclog.NewNullLogger()}
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	c, err := buildConfig(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = c

	return &configv1.ConfigureResponse{}, nil
}

func buildConfig(req *configv1.ConfigureRequest) (*config, error) {
	hclConf := new(Config)
	if err := hcl.Decode(hclConf, req.HclConfiguration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}
	if req.CoreConfiguration == nil {
		return nil, errors.New("core configuration is missing")
	}
	td, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain: %w", err)
	}

	if len(hclConf.RootCas) == 0 {
		return nil, errors.New("root_cas is required")
	}
	cas, err := internal.ReadCerts(hclConf.RootCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read root_cas: %w", err)
	}

	c := &config{
		trustDomain: td,
		rootCas:     cas,
	}

	if hclConf.Policies == "" {
		if hclConf.PolicyEngine != "" {
			return nil, errors.New("policy_engine requires policies")
		}
		return c, nil
	}
	c.policies, err = os.ReadFile(hclConf.Policies)
	if err != nil {
		return nil, fmt.Errorf("failed to read policies: %w", err)
	}
	engine := hclConf.PolicyEngine
	if engine == "" {
		engine = defaultPolicyEngine
	}
	c.policyEngine, err = verifier.ParsePolicyEngine(engine)
	if err != nil {
		return nil, fmt.Errorf("invalid policy_engine: %w", err)
	}

	return c, nil
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	payload := new(na.Payload)
	if err := json.Unmarshal(req.GetPayload(), payload); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal payload: %v", err)
	}
	if payload.Version != na.Version {
		return status.Errorf(codes.InvalidArgument, "unsupported protocol version %q, expected %q",
			payload.Version, na.Version)
	}

	nonce := make([]byte, na.NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return status.Errorf(codes.Internal, "failed to generate nonce: %v", err)
	}
	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{Challenge: nonce},
	}); err != nil {
		return err
	}

	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	report := resp.GetChallengeResponse()
	if len(report) == 0 {
		return status.Error(codes.InvalidArgument, "missing attestation report")
	}

	result := verifier.VerifyBootstrap(report, nonce, c.policies, c.policyEngine, false, c.rootCas)

	attrs, err := agentAttributes(c.trustDomain, result)
	if err != nil {
		p.logger.Warn("Attestation failed", "error", err, "prover", result.Prover.Hostname)
		return status.Errorf(codes.PermissionDenied, "attestation failed: %v", err)
	}
	p.logger.Debug("Attestation succeeded", "agent_id", attrs.SpiffeId, "selectors", attrs.SelectorValues)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{AgentAttributes: attrs},
	})
}

func (p *Plugin) getConfig() (*config, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// agentAttributes maps an attestation result to the agent ID and selectors. Any summary other
// than success rejects the attestation
func agentAttributes(td spiffeid.TrustDomain, result *ar.AttestationResult) (*nodeattestorv1.AgentAttributes, error) {
	if result == nil {
		return nil, errors.New("no attestation result")
	}
	if result.Summary.Status != ar.StatusSuccess {
		return nil, fmt.Errorf("verification status %q, error codes %v", result.Summary.Status,
			result.Summary.ErrorCodes)
	}

	nodeId, err := na.ParseNodeId(string(result.Claims[na.ClaimNodeId]))
	if err != nil {
		return nil, err
	}
	id, err := spiffeid.FromSegments(td, "spire", "agent", na.PluginName, nodeId)
	if err != nil {
		return nil, fmt.Errorf("failed to build agent ID: %w", err)
	}

	return &nodeattestorv1.AgentAttributes{
		SpiffeId:       id.String(),
		SelectorValues: selectorValues(result),
		CanReattest:    true,
	}, nil
}

// selectorValues derives the selector values from the attestation result. The selector type
// (plugin name) is prepended by SPIRE
func selectorValues(result *ar.AttestationResult) []string {
	selectors := []string{"attest-level:" + result.AttestLevel.String()}
	var techs []string
	for _, m := range result.Measurements {
		tech := strings.ToLower(strings.TrimSuffix(m.Type, " Result"))
		if tech != "" && !slices.Contains(techs, tech) {
			techs = append(techs, tech)
		}
	}
	slices.Sort(techs)
	for _, t := range techs {
		selectors = append(selectors, "tech:"+t)
	}
	return selectors
}
