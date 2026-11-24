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
	"context"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/rvps/server"
	"github.com/Fraunhofer-AISEC/cmc/rvps/store"
)

// indexes and blobStores hold the store implementations compiled into the binary, keyed
// by the name they are selected with. They are registered by the build-tagged files
var (
	indexes    = map[string]func(path string) (store.Index, error){}
	blobStores = map[string]func(path string) (store.BlobStore, error){}
)

func available[T any](stores map[string]T) string {
	return strings.Join(slices.Sorted(maps.Keys(stores)), ", ")
}

// binaryName selects the config file and data folder of the binary
const binaryName = "rvps"

func main() {
	// Stop the server gracefully on interrupt or termination
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := &cli.Command{
		Name:    binaryName,
		Usage:   "Reference Value Provider Service storing and providing signed cmc metadata",
		Version: internal.GetVersionInfo().String(),
		Flags:   config.AllFlags(binaryName, &Config{}),
		Action:  serve,
		Commands: []*cli.Command{
			config.Command[Config](binaryName, nil),
		},
	}

	if err := cmd.Run(ctx, os.Args); err != nil {
		config.Fatal(err)
	}
}

func serve(ctx context.Context, cmd *cli.Command) error {

	c, err := config.New[Config](cmd, binaryName)
	if err != nil {
		return err
	}

	if err := c.Log.Setup(); err != nil {
		return err
	}
	config.LogEffective(cmd, binaryName, c, false)
	if err := config.DirsOf(binaryName).Create(); err != nil {
		return err
	}

	log.Infof("Starting RVPS %v", internal.GetVersionInfo())

	if err := c.resolve(); err != nil {
		return err
	}

	// Create or open the index and the blob store (both index and blob store are guaranteed by config to exist)
	index, err := indexes[c.Storage.Index](c.Storage.Db)
	if err != nil {
		return err
	}
	defer index.Close()
	blobs, err := blobStores[c.Storage.BlobStore](c.Storage.Blobs)
	if err != nil {
		return err
	}
	defer blobs.Close()

	// Run the server until the context is cancelled
	srv, err := server.New(index, blobs, c.metadataCas)
	if err != nil {
		return err
	}
	return srv.Serve(ctx, c.Http.Address, c.tlsKey, c.tlsCaChain)
}
