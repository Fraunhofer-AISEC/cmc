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

package verifier

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestValidateConfig(t *testing.T) {
	type args struct {
		reference   map[string]interface{}
		measurement map[string]interface{}
		rules       map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid Exact Match",
			args: args{
				reference:   refConfig,
				measurement: refConfig,
				rules:       rules,
			},
			wantErr: false,
		},
		{
			name: "Valid Derivations",
			args: args{
				reference:   refConfig,
				measurement: validMeasConfig,
				rules:       rules,
			},
			wantErr: false,
		},
		{
			name: "Invalid mandatory deviation 1",
			args: args{
				reference:   refConfig,
				measurement: invalidMandatoryMeasConfig1,
				rules:       rules,
			},
			wantErr: true,
		},
		{
			name: "Invalid mandatory deviation 2",
			args: args{
				reference:   refConfig,
				measurement: invalidMandatoryMeasConfig2,
				rules:       rules,
			},
			wantErr: true,
		},
		{
			name: "Invalid optional deviation",
			args: args{
				reference:   refConfig,
				measurement: invalidOptionalMeasConfig,
				rules:       rules,
			},
			wantErr: true,
		},
		{
			name: "Invalid subset deviation",
			args: args{
				reference:   refConfig,
				measurement: invalidSubsetMeasConfig,
				rules:       rules,
			},
			wantErr: true,
		},
		{
			name: "Invalid implicit deviation",
			args: args{
				reference:   refConfig,
				measurement: invalidImplicitMeasConfig,
				rules:       rules,
			},
			wantErr: true,
		},
		{
			name: "Invalid additional deviation",
			args: args{
				reference:   refConfig,
				measurement: invalidAdditionalMeasConfig,
				rules:       rules,
			},
			wantErr: true,
		},
	}
	logrus.SetLevel(logrus.TraceLevel)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateConfig(tt.args.reference, tt.args.measurement, tt.args.rules); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var (
	// Reference OCI configuration for unit tests
	refConfig = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   refHostName,
		"process":    refProcess,
		"linux":      refLinux,
	}

	refOciVersion = "1.2.0"

	refHostName = "<container-id>"

	refProcess = map[string]interface{}{
		"user":        refUser,
		"args":        refArgs,
		"oomScoreAdj": refOomScoreAdj,
	}

	refUser = map[string]interface{}{
		"uid": 0,
		"gid": 0,
	}

	refArgs = []string{"/bin/bash"}

	refOomScoreAdj = 0

	refLinux = map[string]interface{}{
		"cgroupsPath": "system.slice:docker:<container-id>",
		"seccomp":     refSeccomp,
	}

	refSeccomp = map[string]interface{}{
		"syscalls": refSyscalls,
	}

	refSyscalls = []interface{}{
		refSyscall1,
		refSyscall2,
		refSyscall3,
	}

	refSyscall1 = map[string]interface{}{
		"names":  []interface{}{"accept", "bind"},
		"action": "SCMP_ACT_ALLOW",
	}

	refSyscall2 = map[string]interface{}{
		"names":  []interface{}{"process_vm_readv", "process_vm_writev", "ptrace"},
		"action": "SCMP_ACT_ALLOW",
	}

	refSyscall3 = map[string]interface{}{
		"names":  []interface{}{"chroot"},
		"action": "SCMP_ACT_ALLOW",
	}

	// Measurement configuration testing all valid deviations
	validMeasConfig = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   validMeasHostName,
		"process":    validMeasProcess,
		"linux":      validMeasLinux,
	}

	validMeasHostName = "modified-hostname"

	validMeasProcess = map[string]interface{}{
		"user":            validMeasUser,
		"args":            refArgs,
		"apparmorProfile": additionalApparmoreProfile,
		// optional oomScoreAdj missing
	}

	additionalApparmoreProfile = "docker-default"

	validMeasUser = map[string]interface{}{
		"uid": 0,
		"gid": 10000,
	}

	validMeasLinux = map[string]interface{}{
		"cgroupsPath": "system.slice:docker:<container-id>",
		"seccomp":     validMeasSeccomp,
	}

	validMeasSeccomp = map[string]interface{}{
		"syscalls": validMeasSyscalls,
	}

	validMeasSyscalls = []interface{}{
		validMeasSyscall1,
		refSyscall2,
		validMeasSyscall3,
	}

	validMeasSyscall1 = map[string]interface{}{
		"names":  []interface{}{"accept"},
		"action": "SCMP_ACT_ALLOW",
	}

	validMeasSyscall3 = map[string]interface{}{
		"names":  []interface{}{"arbitrary1", "arbitrary2"},
		"action": "SCMP_ACT_ALLOW",
	}

	// Measurement configurations testing invalid mandatory deviations
	invalidMandatoryMeasConfig1 = map[string]interface{}{
		"ociVersion": invalidMandatoryOciVersion,
		"hostName":   refHostName,
		"process":    refProcess,
		"linux":      refLinux,
	}

	invalidMandatoryMeasConfig2 = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   refHostName,
		"process":    invalidMandatoryProcess,
		"linux":      refLinux,
	}

	invalidMandatoryOciVersion = "1.1.0"

	invalidMandatoryProcess = map[string]interface{}{
		"user":        invalidMandatoryUser,
		"args":        refArgs,
		"oomScoreAdj": refOomScoreAdj,
	}

	invalidMandatoryUser = map[string]interface{}{
		"uid": 1,
		"gid": 0,
	}

	// Measurement configurations testing invalid optional deviations
	invalidOptionalMeasConfig = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   refHostName,
		"process":    invalidOptionalProcess,
		"linux":      refLinux,
	}

	invalidOptionalProcess = map[string]interface{}{
		"user":        refUser,
		"args":        refArgs,
		"oomScoreAdj": invalidOomScorAdj,
	}

	invalidOomScorAdj = 123

	// Measurement configurations testing invalid subset deviations
	invalidSubsetMeasConfig = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   refHostName,
		"process":    refProcess,
		"linux":      invalidSubsetLinux,
	}

	invalidSubsetLinux = map[string]interface{}{
		"cgroupsPath": "system.slice:docker:<container-id>",
		"seccomp":     invalidSubsetSeccomp,
	}

	invalidSubsetSeccomp = map[string]interface{}{
		"syscalls": invalidSubsetSyscalls,
	}

	invalidSubsetSyscalls = []interface{}{
		invalidSubsetSyscall,
		refSyscall2,
		refSyscall3,
	}

	invalidSubsetSyscall = map[string]interface{}{
		"names":  []interface{}{"accept", "invalidbind"},
		"action": "SCMP_ACT_ALLOW",
	}

	// Measurement configurations testing invalid implicit deviations
	invalidImplicitMeasConfig = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   refHostName,
		"process":    invalidImplicitProcess,
		"linux":      refLinux,
	}

	invalidImplicitProcess = map[string]interface{}{
		"user":        refUser,
		"args":        invalidImplicitArgs,
		"oomScoreAdj": refOomScoreAdj,
	}

	invalidImplicitArgs = []string{"/bin/sh"}

	// Measurement configurations testing invalid additional deviations
	invalidAdditionalMeasConfig = map[string]interface{}{
		"ociVersion": refOciVersion,
		"hostName":   refHostName,
		"process":    refProcess,
		"linux":      refLinux,
		"invalid":    invalidImplicitValue,
	}

	invalidImplicitValue = "invalid"

	// Rules for unit tests
	rules = map[string]interface{}{
		"ociVersion": "mandatory",
		"process": map[string]interface{}{
			"apparmorProfile": "additional",
			"oomScoreAdj":     "optional",
			"user": map[string]interface{}{
				"uid": "mandatory",
				"gid": "modifiable",
			},
		},
		"hostName": "modifiable",
		"linux": map[string]interface{}{
			"seccomp": map[string]interface{}{
				"syscalls": []interface{}{
					map[string]interface{}{"names": "subset"},
					map[string]interface{}{"names": "mandatory"},
					map[string]interface{}{"names": "modifiable"},
				},
			},
		},
	}
)
