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

package internal

import (
	"reflect"
	"testing"
)

func TestFilterInts(t *testing.T) {
	type args struct {
		list        []int
		excludeList []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "Exclude PCRs Success",
			args: args{
				list:        []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				excludeList: []int{0, 6, 14, 15},
			},
			want: []int{1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13},
		},
		{
			name: "Exclude No PCRs Success",
			args: args{
				list:        []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				excludeList: []int{},
			},
			want: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterInts(tt.args.list, tt.args.excludeList); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterInts() = %v, want %v", got, tt.want)
			}
		})
	}
}
