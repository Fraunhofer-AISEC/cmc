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
	"bytes"
	"encoding/binary"
	"fmt"
)

type TdReport struct {
	ReportMacStruct ReportMacStruct
	TeeTcbInfo      TeeTcbInfo
	Reserved        [17]byte
	TdInfo          TdInfo
}

type ReportMacStruct struct {
	ReportType     ReportType
	Reserved1      [12]byte
	CpuSvn         [16]byte
	TeeTcbInfoHash [48]byte
	TeeInfoHash    [48]byte
	ReportData     [64]byte
	Reserved2      [32]byte
	Mac            [32]byte
}

type TeeTcbInfo struct {
	Valid        [8]byte
	TeeTcbSvn    [16]byte
	MrSeam       [48]byte
	MrSignerSeam [48]byte
	Attributes   [8]byte
	TeeTcbSvn2   [16]byte
	Reserved     [95]byte
}

type TdInfo struct {
	Attributes    [8]byte
	Xfam          [8]byte
	Mrtd          [48]byte
	MrOwner       [48]byte
	MrOwnerconfig [48]byte
	RtMr0         [48]byte
	RtMr1         [48]byte
	RtMr2         [48]byte
	RtMr3         [48]byte
	Reserved      [64]byte
}

type ReportType struct {
	Type     byte
	SubType  byte
	Version  byte
	Reserved byte
}

func DecodeTdReport(data []byte) (*TdReport, error) {

	var tdReport TdReport

	buf := bytes.NewBuffer(data)

	err := binary.Read(buf, binary.LittleEndian, &tdReport)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDREPORT: %w", err)
	}

	return &tdReport, nil
}
