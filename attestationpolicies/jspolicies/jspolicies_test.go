// Copyright (c) 2021 Fraunhofer AISEC
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

package jspolicies

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestValidate(t *testing.T) {
	type args struct {
		result   []byte
		policies []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Validate Success",
			args: args{
				result:   vrSuccess,
				policies: policies,
			},
			want: true,
		},
		{
			name: "Validate Fail",
			args: args{
				result:   vrFail,
				policies: policies,
			},
			want: false,
		},
	}

	// Setup logger
	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare policy validator
			v := NewJsPolicyEngine(tt.args.policies)

			// Test policy validaton
			got := v.Validate(tt.args.result)
			if got != tt.want {
				t.Errorf("Result.Success = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	vrSuccess = []byte(`
		{
			"type": "Verification Result",
			"raSuccessful": true,
			"rtmValidation": {
				"signatureValidation": [
					{
						"validatedCerts": [
							[
								{
									"subject": {
										"commonName": "Test Cert"
									}
								}
							]
						]
					}
				]
			}
		}
	`)

	vrFail = []byte(`
		{
			"type": "Verification Result",
			"raSuccessful": false,
			"rtmValidation": {
				"signatureValidation": [
				]
			}
		}
	`)

	policies = []byte(`
		// Parse the verification result
		var obj = JSON.parse(json);

		var success = true;

		// Basic checks
		if (obj.type != "Verification Result") {
			console.log("Invalid type");
			success = false;
		}
		if (!obj.raSuccessful) {
			console.log("Attestation not successful")
			success = false;
		}

		// Check a certain certificate property in the RTM Manifest
		var found = false
		for (var i = 0; i < obj.rtmValidation.signatureValidation.length; i++) {
			for (var j = 0; j < obj.rtmValidation.signatureValidation[i].validatedCerts.length; j++) {
				for (var k = 0; k < obj.rtmValidation.signatureValidation[i].validatedCerts[j].length; k++) {
					if (obj.rtmValidation.signatureValidation[i].validatedCerts[j][k].subject.commonName == "Test Cert") {
						found = true;
					}
				}
			}
		}
		if (!found) {
			console.log("Failed to find certificate 'Test Cert'");
			success = false;
		}

		success
	`)
)
