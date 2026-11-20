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

// Package agent implements the agent side of the cmc node attestor. It requests attestation
// reports from the local cmcd via gRPC.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	na "github.com/Fraunhofer-AISEC/cmc/spire/nodeattestor"
)

const (
	defaultCmcAddr = "localhost:9955"
	attestTimeout  = 60 * time.Second
)

// Config is the HCL plugin configuration
type Config struct {
	// CmcAddr is the address of the cmcd gRPC API
	CmcAddr string `hcl:"cmc_addr"`
	// NodeIdPath is the file the node ID is persisted in
	NodeIdPath string `hcl:"node_id_path"`
}

type config struct {
	cmcAddr string
	nodeId  string
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mtx    sync.RWMutex
	config *config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConf := new(Config)
	if err := hcl.Decode(hclConf, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	if hclConf.NodeIdPath == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id_path is required")
	}
	if hclConf.CmcAddr == "" {
		hclConf.CmcAddr = defaultCmcAddr
	}

	nodeId, err := loadOrCreateNodeId(hclConf.NodeIdPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load node ID: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = &config{
		cmcAddr: hclConf.CmcAddr,
		nodeId:  nodeId,
	}

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(na.Payload{Version: na.Version})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal payload: %v", err)
	}
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{Payload: payload},
	}); err != nil {
		return err
	}

	challenge, err := stream.Recv()
	if err != nil {
		return err
	}
	if len(challenge.Challenge) != na.NonceLen {
		return status.Errorf(codes.InvalidArgument, "invalid challenge length %v", len(challenge.Challenge))
	}

	ctx, cancel := context.WithTimeout(stream.Context(), attestTimeout)
	defer cancel()
	report, err := attest(ctx, c.cmcAddr, challenge.Challenge, c.nodeId)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to obtain attestation report: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{ChallengeResponse: report},
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

// attest requests an attestation report for nonce from cmcd, carrying the node ID as claim
func attest(ctx context.Context, addr string, nonce []byte, nodeId string) ([]byte, error) {
	conn, err := grpcapi.NewClient(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cmcd: %w", err)
	}
	defer conn.Close()

	resp, err := grpcapi.NewCMCServiceClient(conn).Attest(ctx, &grpcapi.AttestationRequest{
		Version: grpcapi.GetVersion(),
		Nonce:   nonce,
		Claims:  map[string][]byte{na.ClaimNodeId: []byte(nodeId)},
	})
	if err != nil {
		return nil, fmt.Errorf("attest call failed: %w", err)
	}
	if err := grpcapi.CheckVersion(resp.Version); err != nil {
		return nil, err
	}

	return resp.Report, nil
}

// loadOrCreateNodeId reads the node ID from path or creates and persists a new one
func loadOrCreateNodeId(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return na.ParseNodeId(strings.TrimSpace(string(data)))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	id := uuid.NewString()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	// Write to a temporary file first, so that an interrupted write cannot leave an invalid ID
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return id, nil
}
