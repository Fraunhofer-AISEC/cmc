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

package logging

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
)

func TestRedirectLogrus(t *testing.T) {
	buf := new(bytes.Buffer)
	RedirectLogrus(hclog.New(&hclog.LoggerOptions{Output: buf, Level: hclog.Info}))

	logrus.WithField("service", "ar").Warn("verification failed")
	logrus.Debug("suppressed")

	out := buf.String()
	if !strings.Contains(out, "[WARN]  verification failed: service=ar") {
		t.Errorf("unexpected output %q", out)
	}
	if strings.Contains(out, "suppressed") {
		t.Errorf("debug entry not suppressed: %q", out)
	}
	if logrus.GetLevel() != logrus.InfoLevel {
		t.Errorf("logrus level %v, want info", logrus.GetLevel())
	}
}
