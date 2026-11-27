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

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	na "github.com/Fraunhofer-AISEC/cmc/spire/nodeattestor"
)

const nodeId = "6f1f0b6e-3c4a-4d43-9a8e-2b8f7d1c5e90"

func TestAgentAttributes(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")

	success := func() *ar.AttestationResult {
		return &ar.AttestationResult{
			Summary:     ar.Result{Status: ar.StatusSuccess},
			AttestLevel: ar.LevelHardware,
			Measurements: []ar.MeasurementResult{
				{Type: ar.TYPE_RESULT_TPM},
				{Type: ar.TYPE_RESULT_SNP},
				{Type: ar.TYPE_RESULT_TPM},
			},
			Claims: map[string][]byte{na.ClaimNodeId: []byte(nodeId)},
		}
	}

	tests := []struct {
		name      string
		modify    func(*ar.AttestationResult)
		wantErr   bool
		selectors []string
	}{
		{
			name:      "success",
			modify:    func(*ar.AttestationResult) {},
			selectors: []string{"attest-level:hardware", "tech:snp", "tech:tpm"},
		},
		{
			name: "software",
			modify: func(r *ar.AttestationResult) {
				r.AttestLevel = ar.LevelSoftware
				r.Measurements = []ar.MeasurementResult{{Type: ar.TYPE_RESULT_SW}}
			},
			selectors: []string{"attest-level:software", "tech:sw"},
		},
		{
			name:    "warn rejected",
			modify:  func(r *ar.AttestationResult) { r.Summary.Status = ar.StatusWarn },
			wantErr: true,
		},
		{
			name:    "fail rejected",
			modify:  func(r *ar.AttestationResult) { r.Summary.Status = ar.StatusFail },
			wantErr: true,
		},
		{
			name:    "missing node ID",
			modify:  func(r *ar.AttestationResult) { r.Claims = nil },
			wantErr: true,
		},
		{
			name: "invalid node ID",
			modify: func(r *ar.AttestationResult) {
				r.Claims[na.ClaimNodeId] = []byte("../../server")
			},
			wantErr: true,
		},
		{
			name: "non-canonical node ID",
			modify: func(r *ar.AttestationResult) {
				r.Claims[na.ClaimNodeId] = []byte("{" + nodeId + "}")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := success()
			tc.modify(r)
			attrs, err := agentAttributes(td, r)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := "spiffe://example.org/spire/agent/cmc/" + nodeId; attrs.SpiffeId != want {
				t.Errorf("agent ID %q, want %q", attrs.SpiffeId, want)
			}
			if !slices.Equal(attrs.SelectorValues, tc.selectors) {
				t.Errorf("selectors %v, want %v", attrs.SelectorValues, tc.selectors)
			}
			if !attrs.CanReattest {
				t.Error("expected CanReattest")
			}
		})
	}
}

func TestConfigure(t *testing.T) {
	dir := t.TempDir()
	ca := writeCa(t, dir)
	policies := filepath.Join(dir, "policy.js")
	if err := os.WriteFile(policies, []byte("true"), 0644); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		hcl     string
		td      string
		wantErr bool
	}{
		{name: "minimal", hcl: `root_cas = ["` + ca + `"]`, td: "example.org"},
		{name: "policies", hcl: `root_cas = ["` + ca + `"]
policies = "` + policies + `"`, td: "example.org"},
		{name: "missing root CAs", hcl: ``, td: "example.org", wantErr: true},
		{name: "unreadable root CA", hcl: `root_cas = ["` + dir + `/none.pem"]`, td: "example.org", wantErr: true},
		{name: "engine without policies", hcl: `root_cas = ["` + ca + `"]
policy_engine = "js"`, td: "example.org", wantErr: true},
		{name: "unknown engine", hcl: `root_cas = ["` + ca + `"]
policies = "` + policies + `"
policy_engine = "foo"`, td: "example.org", wantErr: true},
		{name: "publish", hcl: `root_cas = ["` + ca + `"]
publish_results = "https://localhost:8080/results"
publish_token = "` + token + `"
publish_allow_system_certs = true`, td: "example.org"},
		{name: "unreadable publish token", hcl: `root_cas = ["` + ca + `"]
publish_token = "` + dir + `/none"`, td: "example.org", wantErr: true},
		{name: "publish cert without key", hcl: `root_cas = ["` + ca + `"]
publish_cert = "` + ca + `"`, td: "example.org", wantErr: true},
		{name: "invalid trust domain", hcl: `root_cas = ["` + ca + `"]`, td: "Invalid TD", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildConfig(&configv1.ConfigureRequest{
				HclConfiguration:  tc.hcl,
				CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: tc.td},
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestAttestInvalidReport runs the challenge-response flow through the plugin SDK and checks
// that an invalid report is rejected
func TestAttestInvalidReport(t *testing.T) {
	ca := writeCa(t, t.TempDir())

	plugin := New()
	naClient := new(nodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   nodeattestorv1.NodeAttestorPluginServer(plugin),
		PluginClient:   naClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(plugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	ctx := context.Background()
	if _, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		HclConfiguration:  `root_cas = ["` + ca + `"]`,
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
	}); err != nil {
		t.Fatalf("configure: %v", err)
	}

	stream, err := naClient.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(na.Payload{Version: na.Version})
	if err := stream.Send(&nodeattestorv1.AttestRequest{
		Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload},
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetChallenge()) != na.NonceLen {
		t.Fatalf("challenge length %v, want %v", len(resp.GetChallenge()), na.NonceLen)
	}
	if err := stream.Send(&nodeattestorv1.AttestRequest{
		Request: &nodeattestorv1.AttestRequest_ChallengeResponse{ChallengeResponse: []byte("{}")},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func writeCa(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
