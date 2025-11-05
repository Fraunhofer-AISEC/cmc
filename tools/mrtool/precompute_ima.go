// Copyright (c) 2025 Fraunhofer AISEC
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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

type PrecomputeImaConf struct {
	Paths         []string
	Strip         string
	ImaTemplate   string
	BootAggregate []byte
}

const (
	pathFlag          = "path"
	stripFlag         = "strip"
	imaTemplateFlag   = "template"
	bootAggregateFlag = "boot-aggregate"
)

var precomputeImaPcrCommand = &cli.Command{
	Name:  "ima",
	Usage: "Calculates the expected IMA eventlog based on a list of user space software components and configuration files",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  pathFlag,
			Usage: "comma-separated paths or single files (binaries or config files) to create ima reference values for",
		},
		&cli.StringFlag{
			Name:  stripFlag,
			Usage: "Optional path prefix which is stripped from the actual path in the output",
		},
		&cli.StringFlag{
			Name:  imaTemplateFlag,
			Usage: "IMA template name (ima-ng or ima-sig)",
		},
		&cli.StringFlag{
			Name:  bootAggregateFlag,
			Usage: "Boot aggregate (PCRs 0-9) passed as a hex-string to be included as a reference value",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := PrecomputeImaPcr(cmd)
		if err != nil {
			return fmt.Errorf("failed to precompute ima pcr: %w", err)
		}
		return nil
	},
}

func getImaConf(cmd *cli.Command) (*PrecomputeImaConf, error) {

	c := &PrecomputeImaConf{}

	if cmd.IsSet(pathFlag) {
		c.Paths = strings.Split(cmd.String(pathFlag), ",")
	}
	if cmd.IsSet(stripFlag) {
		c.Strip = cmd.String(stripFlag)
	}
	if cmd.IsSet(imaTemplateFlag) {
		c.ImaTemplate = cmd.String(imaTemplateFlag)
	}
	if cmd.IsSet(bootAggregateFlag) {
		b, err := hex.DecodeString(cmd.String(bootAggregateFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to read boot-aggregate hex string: %w", err)
		}
		c.BootAggregate = b
	}

	printImaConf(c)

	return c, nil
}

func checkImaConf(globConf *GlobalConfig, c *PrecomputeImaConf) error {
	if c.ImaTemplate != "ima-sig" && c.ImaTemplate != "ima-ng" {
		return fmt.Errorf("unsupported ima template %q. Expect ima-sig or ima-ng. See mrtool precompute ima --help",
			c.ImaTemplate)
	}
	if len(c.Paths) == 0 && c.BootAggregate == nil {
		return fmt.Errorf("no paths and no boot-aggregate specified. See mrtool precompute ima --help")
	}
	if c.BootAggregate != nil && len(c.BootAggregate) != 32 {
		return fmt.Errorf("unexpected boot aggregate length %v", len(c.BootAggregate))
	}
	if len(globConf.Mrs) != 1 {
		return fmt.Errorf("unexpected mrs length %v (expect exactly 1 PCR specified via --mrs). See mrtool precompute ima --help",
			len(globConf.Mrs))
	}
	if globConf.PrintSummary {
		return fmt.Errorf("summary not yet implemented for mrtool precompute ima. See mrtool precompute ima --help")
	}
	return nil
}

func printImaConf(c *PrecomputeImaConf) {

	log.Debugf("IMA Config")
	log.Debugf("\tima-template  : %q", c.ImaTemplate)
	if len(c.Paths) > 0 {
		log.Debugf("\tPaths         :")
		for _, path := range c.Paths {
			log.Debugf("\t\t%q", path)
		}
	}
	if c.Strip != "" {
		log.Debugf("\tstrip         : %q", c.Strip)
	}
	if c.BootAggregate != nil {
		log.Debugf("\tboot-aggregate: %q", hex.EncodeToString(c.BootAggregate))
	}
}

func PrecomputeImaPcr(cmd *cli.Command) error {

	globConf, err := getGlobalConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	imaConf, err := getImaConf(cmd)
	if err != nil {
		return fmt.Errorf("invalid ima config: %w", err)
	}

	err = checkImaConf(globConf, imaConf)
	if err != nil {
		return fmt.Errorf("failed to check IMA config: %w", err)
	}

	log.Debug("Precomputing IMA PCR...")

	// Precompute all IMA measurements
	refvals, err := performImaPrecomputation(globConf.Mrs[0], imaConf.BootAggregate, imaConf.Paths, imaConf.Strip, imaConf.ImaTemplate)
	if err != nil {
		return err
	}

	// Marshal eventlog
	data, err := json.MarshalIndent(refvals, "", "     ")
	if err != nil {
		return fmt.Errorf("failed to marshal reference values: %w", err)
	}

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	log.Debug("Finished")

	return nil
}

func performImaPrecomputation(pcr int, bootAggregate []byte, paths []string, strip string, imaTemplate string) ([]*ar.ReferenceValue, error) {

	refvals := make([]*ar.ReferenceValue, 0)
	fileCh := make(chan string, 100)
	resultCh := make(chan *ar.ReferenceValue, 100)

	if bootAggregate != nil {
		log.Debugf("Precomputing boot aggregate...")

		refval, err := precomputeImaBootAggregate(bootAggregate, imaTemplate, pcr, false)
		if err != nil {
			return nil, fmt.Errorf("failed to precompute boot_aggregate: %w", err)
		}
		refvals = append(refvals, refval)
	}

	log.Debugf("Precomputing %v paths...", len(paths))

	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU() / 2
	log.Debugf("Using %v workers", numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				refval, err := precomputeImaEntry(path, strip, imaTemplate, pcr, true)
				if err != nil {
					log.Debugf("error hashing %q: %v", path, err)
					continue
				}
				log.Tracef("%s: %s", refval.SubType, hex.EncodeToString(refval.Sha256))
				resultCh <- refval
			}
		}()
	}

	// Collector goroutine
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for r := range resultCh {
			refvals = append(refvals, r)
		}
	}()

	// Walk all given paths
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Debugf("error accessing %q: %v", path, err)
				return nil
			}
			if info.Mode().IsRegular() {
				fileCh <- path
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking the path %q: %w", root, err)
		}
	}

	close(fileCh)
	wg.Wait()
	close(resultCh)
	collectWg.Wait()

	return refvals, nil
}

func precomputeImaTemplate(hash []byte, path string, template string) ([]byte, error) {

	const hashAlgo = "sha256:"
	if len(hash) != sha256.Size {
		return nil, fmt.Errorf("unexpected hash length %v", len(hash))
	}

	imaDigestLen := uint32(len(hashAlgo) + 1 + sha256.Size)
	pathLen := uint32(len(path) + 1)
	sigLen := uint32(0)

	var tmpl []byte

	switch template {
	case "ima-sig":
		tmpl = buildTemplate(hashAlgo, hash, path, imaDigestLen, pathLen, &sigLen)

	case "ima-ng":
		tmpl = buildTemplate(hashAlgo, hash, path, imaDigestLen, pathLen, nil)

	default:
		return nil, fmt.Errorf("template %q not supported", template)
	}

	th := sha256.Sum256(tmpl)

	return th[:], nil
}

func precomputeImaBootAggregate(hash []byte, template string, pcr int, optional bool) (*ar.ReferenceValue, error) {

	tmpl, err := precomputeImaTemplate(hash, "boot_aggregate", template)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute ima template: %w", err)
	}

	// Create reference value
	r := &ar.ReferenceValue{
		Type:     "TPM Reference Value",
		SubType:  "boot_aggregate",
		Index:    pcr,
		Sha256:   tmpl,
		Optional: optional,
	}

	return r, nil
}

func precomputeImaEntry(path, strip, template string, pcr int, optional bool) (*ar.ReferenceValue, error) {

	fileHash, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	strippedPath := stripPrefix(path, strip)

	tmpl, err := precomputeImaTemplate(fileHash, strippedPath, template)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute ima template: %w", err)
	}

	// Create reference value
	r := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     filepath.Base(strippedPath),
		Index:       pcr,
		Sha256:      tmpl,
		Description: strippedPath,
		Optional:    optional,
	}

	return r, nil
}

func buildTemplate(hashAlgo string, hash []byte, path string, imaDigestLen, pathLen uint32, sigLen *uint32) []byte {
	var buf []byte

	// ima_digest_len
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, imaDigestLen)
	buf = append(buf, tmp...)

	// hashAlgo + NUL
	buf = append(buf, []byte(hashAlgo)...)
	buf = append(buf, 0)

	// sha256 hash
	buf = append(buf, hash...)

	// path_len
	binary.LittleEndian.PutUint32(tmp, pathLen)
	buf = append(buf, tmp...)

	// path + NUL
	buf = append(buf, []byte(path)...)
	buf = append(buf, 0)

	// sig_len if ima-sig
	if sigLen != nil {
		binary.LittleEndian.PutUint32(tmp, *sigLen)
		buf = append(buf, tmp...)
	}

	return buf
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func stripPrefix(s, prefix string) string {
	if s == "" {
		return ""
	}
	if prefix != "" && strings.HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}
