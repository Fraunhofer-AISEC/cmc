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
	"testing"

	"github.com/gin-gonic/gin"
)

var (
	validId        = "123deadcafe"
	invalidId      = "123xy7"
	invalidIdSpace = "123 456"

	validName        = "de.test.prover"
	invalidName      = "de.test.prover\n"
	invalidNameSpace = "de.te st.prover"
)

func Test_getId(t *testing.T) {
	tests := []struct {
		name    string
		c       *gin.Context
		want    string
		wantErr bool
	}{
		{
			name: "Success ID",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "id",
						Value: validId,
					},
				},
			},
			want:    validId,
			wantErr: false,
		},
		{
			name: "Fail ID invalid character",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "id",
						Value: invalidId,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Fail ID invalid space",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "id",
						Value: invalidIdSpace,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Fail ID invalid key",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "idx",
						Value: validId,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := getId(tt.c)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getId() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getId() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("getId() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getName(t *testing.T) {
	tests := []struct {
		name    string
		c       *gin.Context
		want    string
		wantErr bool
	}{
		{
			name: "Success Name",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "name",
						Value: validName,
					},
				},
			},
			want:    validName,
			wantErr: false,
		},
		{
			name: "Fail Name invalid character",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "name",
						Value: invalidName,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Fail Name invalid space",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "name",
						Value: invalidNameSpace,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Fail Name invalid key",
			c: &gin.Context{
				Params: []gin.Param{
					{
						Key:   "namex",
						Value: validName,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := getName(tt.c)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getName() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getName() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("getName() = %v, want %v", got, tt.want)
			}
		})
	}
}
