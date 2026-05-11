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
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/tools/ctrtool/convert"
	"github.com/Fraunhofer-AISEC/cmc/tools/ctrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/ctrtool/measure"
)

func main() {
	cmd := &cli.Command{
		Name:  "metatool",
		Usage: "A tool for measuring and converting OCI images and OCI runtime bundles",
		Flags: global.Flags,
		Commands: []*cli.Command{
			convert.Command,
			measure.Command,
		},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
