// Copyright(c) 2025 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the License); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/exp/maps"

	log "github.com/sirupsen/logrus"
)

type hashJob struct {
	file    string
	outfile string
}

var (
	logLevels = map[string]log.Level{
		"panic": log.PanicLevel,
		"fatal": log.FatalLevel,
		"error": log.ErrorLevel,
		"warn":  log.WarnLevel,
		"info":  log.InfoLevel,
		"debug": log.DebugLevel,
		"trace": log.TraceLevel,
	}
)

func main() {

	outputDir := flag.String("out", "collected-refvals", "Directory to output hash files to (default: collected-refvals)")
	distribution := flag.String("os", "ubuntu", "OS distribution to be used (default: ubuntu)")
	parallelCount := flag.Int("cpus", runtime.NumCPU(), "Defined how many files are hashed concurrently (default: #CPUs)")
	logLevel := flag.String("log", "info",
		fmt.Sprintf("Possible logging levels (default: info): %v", strings.Join(maps.Keys(logLevels), ",")))
	flag.Parse()

	l, ok := logLevels[strings.ToLower(*logLevel)]
	if !ok {
		log.Errorf("log level %v does not exist", *logLevel)
		os.Exit(1)
	}
	log.SetLevel(l)

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Errorf("failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	var pkgs []string
	var err error

	switch *distribution {
	case "ubuntu":
		log.Info("Fetching package list...")
		pkgs, err = getPackages()
		if err != nil {
			log.Errorf("Failed to list packages: %v", err)
			os.Exit(1)
		}
		for _, pkg := range pkgs {
			log.Tracef("    %v", pkg)
		}
	default:
		log.Errorf("Distribution %v is not supported", *distribution)
		os.Exit(1)
	}

	log.Infof("Found %d packages", len(pkgs))
	jobs := make(chan hashJob, 1024)
	var wg sync.WaitGroup

	// Start worker pool
	log.Info("Hashing packages (this might take a while)")
	for i := 0; i < *parallelCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				hashFile(job.file, job.outfile)
			}
		}()
	}

	// Iterate over packages and enqueue file hashing
	for _, pkg := range pkgs {
		files, err := getPackageFiles(pkg)
		if err != nil {
			log.Warnf("Skipping %s: %v", pkg, err)
			continue
		}
		outfile := filepath.Join(*outputDir, pkg+".hashes")

		// Clear the file before appending
		if err := os.WriteFile(outfile, []byte{}, 0644); err != nil {
			log.Warnf("Error creating %s: %v", outfile, err)
			continue
		}

		for _, f := range files {
			if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() {
				jobs <- hashJob{file: f, outfile: outfile}
			}
		}
	}

	close(jobs)
	wg.Wait()

	log.Info("Done.")
}

func getPackages() ([]string, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines, nil
}

func getPackageFiles(pkg string) ([]string, error) {
	cmd := exec.Command("dpkg", "-L", pkg)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	return files, nil
}

var mu sync.Mutex

func hashFile(path, outfile string) {
	f, err := os.Open(path)
	if err != nil {
		return // ignore unreadable files
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	line := fmt.Sprintf("%s=%s\n", path, sum)

	mu.Lock()
	defer mu.Unlock()
	fout, err := os.OpenFile(outfile, os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		defer fout.Close()
		fout.WriteString(line)
	}
}
