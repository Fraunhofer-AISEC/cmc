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

package duktape

import (
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/sirupsen/logrus"
)

func TestValidate(t *testing.T) {
	type args struct {
		result          *ar.VerificationResult
		policies        []byte
		policyOverwrite bool
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 ar.Status
	}{
		{
			name: "Validate Cert Check Success",
			args: args{
				result:          vrValidCerts,
				policies:        readPolicies,
				policyOverwrite: false,
			},
			want:  true,
			want1: ar.StatusSuccess,
		},
		{
			name: "Validate Cert Check Fail",
			args: args{
				result:          vrInvalidCerts,
				policies:        readPolicies,
				policyOverwrite: false,
			},
			want:  false,
			want1: ar.StatusSuccess, // The result itself is not changed in this test
		},
		{
			name: "Validate Change Result Success",
			args: args{
				result:          vrFailModifiable,
				policies:        writePolicies,
				policyOverwrite: true,
			},
			want:  true,
			want1: ar.StatusWarn, // The result is changed to warn in this test
		},
		{
			name: "Validate Change Result No Overwrite",
			args: args{
				result:          vrFail,
				policies:        writePolicies,
				policyOverwrite: false,
			},
			want:  false,
			want1: ar.StatusFail, // The result may not be changed in this test
		},
	}

	// Setup logger
	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			log.Infof("Running unit test %q", tt.name)

			p := DukTapePolicyEngine{}

			// Test policy validaton
			got := p.Validate(tt.args.result, tt.args.policies, tt.args.policyOverwrite)
			if got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
			if tt.args.result.Summary.Status != tt.want1 {
				t.Errorf("Result.Summary.Status = %v, want %v", tt.args.result.Summary.Status, tt.want1)
			}
		})
	}
}

var (
	vrValidCerts = &ar.VerificationResult{
		Prover: "Test Prover",
		Type:   "Verification Result",
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
		Metadata: ar.MetadataSummary{
			DevDescResult: ar.MetadataResult{
				SignatureCheck: []ar.SignatureResult{
					{
						Certs: [][]ar.X509CertExtracted{
							{
								{
									Subject: ar.X509Name{
										CommonName: "CMC Test Leaf Certificate",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	vrInvalidCerts = &ar.VerificationResult{
		Prover: "Test Prover",
		Type:   "Verification Result",
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
		Metadata: ar.MetadataSummary{
			DevDescResult: ar.MetadataResult{
				SignatureCheck: []ar.SignatureResult{
					{
						Certs: [][]ar.X509CertExtracted{
							{
								{
									Subject: ar.X509Name{
										CommonName: "INVALID CERT",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// This variable is actually manipulated and cannot be reused
	vrFailModifiable = &ar.VerificationResult{
		Prover: "Test Prover",
		Type:   "Verification Result",
		Summary: ar.Result{
			Status: ar.StatusFail,
		},
	}

	vrFail = &ar.VerificationResult{
		Prover: "Test Prover",
		Type:   "Verification Result",
		Summary: ar.Result{
			Status: ar.StatusFail,
		},
	}

	readPolicies = []byte(`
		// Parse the verification result
		var obj = JSON.parse(json);

		var success = true;

		// Basic checks
		if (obj.type != "Verification Result") {
			success = false;
		}
		if (obj.summary.status != "success") {
			success = false;
		}

		// Check a certain certificate property in the device description
		var found = false
		for (var i = 0; i < obj.metadata.devDescResult.signatureValidation.length; i++) {
			for (var j = 0; j < obj.metadata.devDescResult.signatureValidation[i].certs.length; j++) {
				for (var k = 0; k < obj.metadata.devDescResult.signatureValidation[i].certs[j].length; k++) {
					if (obj.metadata.devDescResult.signatureValidation[i].certs[j][k].subject.commonName == "CMC Test Leaf Certificate") {
						found = true;
					}
				}
			}
		}
		if (!found) {
			success = false;
		}

		success
	`)

	writePolicies = []byte(`
		// Parse the verification result
		var obj = JSON.parse(json);

		// Basic checks
		if (obj.type != "Verification Result") {
			success = false;
		}

		// Change the overall result to warn
		obj.summary.status = "warn"

		var ret = JSON.stringify(obj);

		ret
	`)
)
