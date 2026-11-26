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

//go:build linux && cgo && (!nodefaults || nvidia)

package nvidiadriver

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// TestMain builds the fake NVML library from testdata/fake_nvml.c and loads it instead of
// libnvidia-ml.so. Run with -asan to detect NVML writes beyond the passed buffers.
func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "fakenvml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)

	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	lib := filepath.Join(dir, "libnvidia-ml.so")
	out, err := exec.Command(cc, "-shared", "-fPIC", "-Wall", "-Werror", "-o", lib,
		filepath.Join("testdata", "fake_nvml.c")).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build fake NVML library: %v\n%s", err, out)
		return 1
	}

	nvmlLibs = []string{lib}
	if err := nvmlLoad(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load fake NVML library: %v\n", err)
		return 1
	}

	return m.Run()
}

func TestQueryNonAttestationReportMeasurements(t *testing.T) {
	dev, err := GetHandle(0)
	if err != nil {
		t.Fatalf("GetHandle: %v", err)
	}

	got, err := QueryNonAttestationReportMeasurements(dev)
	if err != nil {
		t.Fatalf("QueryNonAttestationReportMeasurements: %v", err)
	}

	want := internal.NvidiaDeviceUnsignedEvidence{
		UUID:                  "GPU-01234567-89ab-cdef-0123-456789abcdef",
		InforomOemVersion:     "G520.0200.00.05",
		InforomEccVersion:     "7.0",
		InforomPowerVersion:   "N/A",
		InforomImageVersion:   "G520.0200.00.04",
		InforomConfigChecksum: "0x0badc0de",
		GspFirmwareVersion:    strings.Repeat("g", 63),
		GspFirmwareIsEnabled:  true,
		GspFirmwareDefault:    true,
		InforomIsValid:        true,
		MigCurrentMode:        0,
		MigPendingMode:        1,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestQueryGPUs(t *testing.T) {
	gpus, err := QueryGPUs()
	if err != nil {
		t.Fatalf("QueryGPUs: %v", err)
	}

	want := []GPUInfo{{
		Index:         0,
		DeviceName:    "NVIDIA H100 NVL",
		DeviceUUID:    "GPU-01234567-89ab-cdef-0123-456789abcdef",
		DriverVersion: "595.71.05",
		VBIOSVersion:  "96.00.A5.00.01",
		certs:         "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
	}}
	if len(gpus) != len(want) || gpus[0] != want[0] {
		t.Errorf("got %+v, want %+v", gpus, want)
	}
}

func TestQueryGPUAttestationReport(t *testing.T) {
	dev, err := GetHandle(0)
	if err != nil {
		t.Fatalf("GetHandle: %v", err)
	}

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	report, err := QueryGPUAttestationReport(dev, nonce)
	if err != nil {
		t.Fatalf("QueryGPUAttestationReport: %v", err)
	}
	if want := bytes.Repeat(nonce, 2); !bytes.Equal(report, want) {
		t.Errorf("got report %x, want %x", report, want)
	}

	if _, err := QueryGPUAttestationReport(dev, nonce[:16]); err == nil {
		t.Error("expected error for short nonce")
	}
}
