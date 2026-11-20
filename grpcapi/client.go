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

package grpcapi

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Fraunhofer-AISEC/cmc/api"
)

// Target converts a cmc address into a gRPC target. Addresses are interpreted as for the socket
// API (see api.GetNetworkAndAddr), i.e. TCP or unix domain sockets are supported
func Target(addr string) string {
	network, a := api.GetNetworkAndAddr(addr)
	if network == "unix" {
		return "unix:" + a
	}
	return a
}

// NewClient creates a gRPC client connection to the cmcd at the specified address
func NewClient(addr string) (*grpc.ClientConn, error) {
	return grpc.NewClient(Target(addr), grpc.WithTransportCredentials(insecure.NewCredentials()))
}
