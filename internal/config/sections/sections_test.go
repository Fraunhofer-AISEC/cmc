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

package sections

import (
	"reflect"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/certpolicy"
)

func TestCertPolicyArcDefault(t *testing.T) {
	f, _ := reflect.TypeFor[CertPolicy]().FieldByName("Arc")
	if got := f.Tag.Get("default"); got != certpolicy.DefaultArc {
		t.Errorf("default cert_policy.arc = %v, want certpolicy.DefaultArc %v", got, certpolicy.DefaultArc)
	}
}
