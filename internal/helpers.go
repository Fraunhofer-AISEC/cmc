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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "internal")

func FileExists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	}
	return false
}

func Contains(elem string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(s, elem) {
			return true
		}
	}
	return false
}

func FlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// Tests if the address is a network address in the form ip:port. In this
// case, returns "tcp" to be used as the transport layer, otherwise assumes
// that the address is a unix domain socket
func GetNetworkAndAddr(addr string) (string, string, error) {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return "tcp", addr, nil
	} else {
		a, err := filepath.Abs(addr)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse address '%v': %w", addr, err)
		}
		return "unix", a, nil
	}
}

// IndexToMr uses the mapping according to UEFI Spec 2.10 Section 38.4.1
func IndexToMr(index int) string {
	switch index {
	case 0:
		return "MRTD"
	case 1:
		return "RTMR0"
	case 2:
		return "RTMR1"
	case 3:
		return "RTMR2"
	case 4:
		return "RTMR3"
	case 5:
		return "MRSEAM"
	default:
		return "UNKNOWN"
	}
}

// FormatRtmrData formats the RTMR data to a string if the data is printable
func FormatRtmrData(data []byte) string {
	for _, b := range data {
		if b > 127 || !unicode.IsPrint(rune(b)) {
			return ""
		}
	}
	return string(data)
}

func ConvertToMap(metadata [][]byte) map[string][]byte {
	metamap := make(map[string][]byte)
	for _, m := range metadata {
		hash := sha256.Sum256(m)
		metamap[hex.EncodeToString(hash[:])] = m
	}
	return metamap
}

func ConvertToArray(metamap map[string][]byte) [][]byte {
	metadata := make([][]byte, 0, len(metamap))
	for _, v := range metamap {
		metadata = append(metadata, v)
	}
	return metadata
}

func FlattenArray(data [][]byte) []byte {
	var buf bytes.Buffer
	for _, part := range data {
		binary.Write(&buf, binary.BigEndian, uint32(len(part)))
		buf.Write(part)
	}
	return buf.Bytes()
}

func UnflattenArray(data []byte) ([][]byte, error) {
	var result [][]byte
	buf := bytes.NewReader(data)
	for buf.Len() > 0 {
		var length uint32
		if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		chunk := make([]byte, length)
		if _, err := io.ReadFull(buf, chunk); err != nil {
			return nil, err
		}
		result = append(result, chunk)
	}
	return result, nil
}

func StrToInt(strs []string) ([]int, error) {
	ints := make([]int, len(strs))
	for i, s := range strs {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q: %w", s, err)
		}
		ints[i] = n
	}
	return ints, nil
}

func FilterInts(list, excludeList []int) []int {
	filtered := make([]int, 0, len(list))
	for _, p := range list {
		found := false
		for _, e := range excludeList {
			if e == p {
				found = true
				break
			}
		}
		if !found {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
