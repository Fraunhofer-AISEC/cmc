// Copyright (c) 2024 Fraunhofer AISEC
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
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/sirupsen/logrus"
)

func Test_validateQEIdentityProperties(t *testing.T) {
	type args struct {
		qeReportBody *EnclaveReportBody
		qeIdentity   *pcs.QeIdentity
		teeType      QuoteType
	}
	tests := []struct {
		name string
		args args
		want ar.QeReportResult
	}{
		{
			name: "Valid QE Identity",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   validQeIdentity,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: true,
				},
			},
		},
		{
			name: "Invalid TEE Type",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   validQeIdentity,
				teeType:      0xFF,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid ID",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidId,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid Version",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidVersion,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid Next Update",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityExpired,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid MISCSELECT",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidMiscSelect,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid Attributes",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidAttributes,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid MRSIGNER",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidMrSigner,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid ISVPRODID",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidIsvProdId,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
		{
			name: "Invalid TCB Levels",
			args: args{
				qeReportBody: reportBody,
				qeIdentity:   qeIdentityInvalidTcbLevels,
				teeType:      TDX_QUOTE_TYPE,
			},
			want: ar.QeReportResult{
				Summary: ar.Result{
					Success: false,
				},
			},
		},
	}

	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateQEIdentityProperties(tt.args.qeReportBody, tt.args.qeIdentity, tt.args.teeType)
			if got.Summary.Success != tt.want.Summary.Success {
				t.Errorf("validateQEIdentityProperties() success = %v, wantSuccess %v", got.Summary.Success, tt.want.Summary.Success)
			}
		})
	}
}

var (
	reportBody = &EnclaveReportBody{
		CPUSVN:     [16]byte{0x0},
		MISCSELECT: 0x0,
		Reserved1:  [28]byte{0x0},
		Attributes: [16]byte{0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		MRENCLAVE:  [32]byte{0x0},
		Reserved2:  [32]byte{0x0},
		MRSIGNER: [32]byte{
			0xdc, 0x9e, 0x2a, 0x7c, 0x6f, 0x94, 0x8f, 0x17,
			0x47, 0x4e, 0x34, 0xa7, 0xfc, 0x43, 0xed, 0x03,
			0x0f, 0x7c, 0x15, 0x63, 0xf1, 0xba, 0xbd, 0xdf,
			0x63, 0x40, 0xc8, 0x2e, 0x0e, 0x54, 0xa8, 0xc5},
		Reserved3:  [96]byte{0x0},
		ISVProdID:  0x2,
		ISVSVN:     0x4,
		Reserved4:  [60]byte{0x0},
		ReportData: [64]byte{0x0},
	}

	// Retrieve current JSON via: tdxquote -cmd qeidentity
	validMiscselect     = pcs.HexBytes{Bytes: dec("00000000")}
	validMiscselectMask = pcs.HexBytes{Bytes: dec("FFFFFFFF")}
	validAttributes     = pcs.HexBytes{Bytes: dec("11000000000000000000000000000000")}
	validAttributesMask = pcs.HexBytes{Bytes: dec("FBFFFFFFFFFFFFFF0000000000000000")}
	validMrsigner       = pcs.HexBytes{Bytes: dec("DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5")}

	invalidMiscselect = pcs.HexBytes{Bytes: dec("AAAAAAAA")}
	invalidAttributes = pcs.HexBytes{Bytes: dec("00000000000000000000000000000000")}
	invalidMrsigner   = pcs.HexBytes{Bytes: dec("AAAA2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5")}

	validTcbLevels = []pcs.TcbLevel{
		{
			Tcb: pcs.Tcb{
				Isvsvn: 4,
			},
			TcbDate:   "2024-03-13T00:00:00Z",
			TcbStatus: "UpToDate",
		},
	}

	invalidTcbLevels = []pcs.TcbLevel{
		{
			Tcb: pcs.Tcb{
				Isvsvn: 4,
			},
			TcbDate:   "2024-03-13T00:00:00Z",
			TcbStatus: "Revoked",
		},
	}

	validQeIdentity = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidId = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "XXXXXXXX",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidVersion = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 70,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityExpired = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(-24 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidMiscSelect = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              invalidMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidAttributes = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              invalidAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidMrSigner = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                invalidMrsigner,
			IsvProdID:               2,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidIsvProdId = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               70,
			TcbLevels:               validTcbLevels,
		},
	}

	qeIdentityInvalidTcbLevels = &pcs.QeIdentity{
		EnclaveIdentity: pcs.EnclaveIdentity{
			ID:                      "TD_QE",
			Version:                 2,
			IssueDate:               time.Now().Add(-24 * time.Hour),
			NextUpdate:              time.Now().Add(1000 * time.Hour),
			TcbEvaluationDataNumber: 17,
			Miscselect:              validMiscselect,
			MiscselectMask:          validMiscselectMask,
			Attributes:              validAttributes,
			AttributesMask:          validAttributesMask,
			Mrsigner:                validMrsigner,
			IsvProdID:               2,
			TcbLevels:               invalidTcbLevels,
		},
	}
)
