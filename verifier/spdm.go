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

package verifier

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type GpuOpaqueDataType uint16

const (
	GpuOpaqueDataTypeUnknown                    GpuOpaqueDataType = 0
	GpuOpaqueDataTypeCertIssuerName             GpuOpaqueDataType = 1
	GpuOpaqueDataTypeCertAuthorityKeyIdentifier GpuOpaqueDataType = 2
	GpuOpaqueDataTypeDriverVersion              GpuOpaqueDataType = 3
	GpuOpaqueDataTypeGpuInfo                    GpuOpaqueDataType = 4
	GpuOpaqueDataTypeSku                        GpuOpaqueDataType = 5
	GpuOpaqueDataTypeVbiosVersion               GpuOpaqueDataType = 6
	GpuOpaqueDataTypeManufacturerId             GpuOpaqueDataType = 7
	GpuOpaqueDataTypeTamperDetection            GpuOpaqueDataType = 8
	GpuOpaqueDataTypeSmc                        GpuOpaqueDataType = 9
	GpuOpaqueDataTypeVpr                        GpuOpaqueDataType = 10
	GpuOpaqueDataTypeNvdec0Status               GpuOpaqueDataType = 11
	GpuOpaqueDataTypeMsrscnt                    GpuOpaqueDataType = 12
	GpuOpaqueDataTypeCprinfo                    GpuOpaqueDataType = 13
	GpuOpaqueDataTypeBoardId                    GpuOpaqueDataType = 14
	GpuOpaqueDataTypeChipSku                    GpuOpaqueDataType = 15
	GpuOpaqueDataTypeChipSkuMod                 GpuOpaqueDataType = 16
	GpuOpaqueDataTypeProject                    GpuOpaqueDataType = 17
	GpuOpaqueDataTypeProjectSku                 GpuOpaqueDataType = 18
	GpuOpaqueDataTypeProjectSkuMod              GpuOpaqueDataType = 19
	GpuOpaqueDataTypeFwid                       GpuOpaqueDataType = 20
	GpuOpaqueDataTypeProtectedPcieStatus        GpuOpaqueDataType = 21
	GpuOpaqueDataTypeSwitchPdi                  GpuOpaqueDataType = 22
	GpuOpaqueDataTypeFloorsweptPorts            GpuOpaqueDataType = 23
	GpuOpaqueDataTypePositionId                 GpuOpaqueDataType = 24
	GpuOpaqueDataTypeLockSwitchStatus           GpuOpaqueDataType = 25
	GpuOpaqueDataTypeGpuLinkConn                GpuOpaqueDataType = 32
	GpuOpaqueDataTypeSysEnableStatus            GpuOpaqueDataType = 33
	GpuOpaqueDataTypeOpaqueDataVersion          GpuOpaqueDataType = 34
	GpuOpaqueDataTypeChipInfo                   GpuOpaqueDataType = 35
	GpuOpaqueDataTypeFeatureFlag                GpuOpaqueDataType = 36
	GpuOpaqueDataTypeInvalid                    GpuOpaqueDataType = 255
)

func (g GpuOpaqueDataType) String() string {
	switch g {
	case GpuOpaqueDataTypeUnknown:
		return "UNKNOWN"
	case GpuOpaqueDataTypeCertIssuerName:
		return "CERT_ISSUER_NAME"
	case GpuOpaqueDataTypeCertAuthorityKeyIdentifier:
		return "CERT_AUTHORITY_KEY_IDENTIFIER"
	case GpuOpaqueDataTypeDriverVersion:
		return "DRIVER_VERSION"
	case GpuOpaqueDataTypeGpuInfo:
		return "GPU_INFO"
	case GpuOpaqueDataTypeSku:
		return "SKU"
	case GpuOpaqueDataTypeVbiosVersion:
		return "VBIOS_VERSION"
	case GpuOpaqueDataTypeManufacturerId:
		return "MANUFACTURER_ID"
	case GpuOpaqueDataTypeTamperDetection:
		return "TAMPER_DETECTION"
	case GpuOpaqueDataTypeSmc:
		return "SMC"
	case GpuOpaqueDataTypeVpr:
		return "VPR"
	case GpuOpaqueDataTypeNvdec0Status:
		return "NVDEC0_STATUS"
	case GpuOpaqueDataTypeMsrscnt:
		return "MSRSCNT"
	case GpuOpaqueDataTypeCprinfo:
		return "CPRINFO"
	case GpuOpaqueDataTypeBoardId:
		return "BOARD_ID"
	case GpuOpaqueDataTypeChipSku:
		return "CHIP_SKU"
	case GpuOpaqueDataTypeChipSkuMod:
		return "CHIP_SKU_MOD"
	case GpuOpaqueDataTypeProject:
		return "PROJECT"
	case GpuOpaqueDataTypeProjectSku:
		return "PROJECT_SKU"
	case GpuOpaqueDataTypeProjectSkuMod:
		return "PROJECT_SKU_MOD"
	case GpuOpaqueDataTypeFwid:
		return "FWID"
	case GpuOpaqueDataTypeProtectedPcieStatus:
		return "PROTECTED_PCIE_STATUS"
	case GpuOpaqueDataTypeSwitchPdi:
		return "SWITCH_PDI"
	case GpuOpaqueDataTypeFloorsweptPorts:
		return "FLOORSWEPT_PORTS"
	case GpuOpaqueDataTypePositionId:
		return "POSITION_ID"
	case GpuOpaqueDataTypeLockSwitchStatus:
		return "LOCK_SWITCH_STATUS"
	case GpuOpaqueDataTypeGpuLinkConn:
		return "GPU_LINK_CONN"
	case GpuOpaqueDataTypeSysEnableStatus:
		return "SYS_ENABLE_STATUS"
	case GpuOpaqueDataTypeOpaqueDataVersion:
		return "OPAQUE_DATA_VERSION"
	case GpuOpaqueDataTypeChipInfo:
		return "CHIP_INFO"
	case GpuOpaqueDataTypeFeatureFlag:
		return "FEATURE_FLAG"
	case GpuOpaqueDataTypeInvalid:
		return "INVALID"
	default:
		return fmt.Sprintf("GpuOpaqueDataType(%d)", g)
	}
}

const (
	SPDM_REQUEST_SpdmVersionSize         = 1
	SPDM_REQUEST_RequestResponseCodeSize = 1
	SPDM_REQUEST_Param1Size              = 1
	SPDM_REQUEST_Param2Size              = 1
	SPDM_REQUEST_NonceSize               = 32
	SPDM_REQUEST_SlotIDParamSize         = 1
	SPDM_REQUEST_kRequestLength          = 37 // 1 + 1 + 1 + 1 + 32 + 1

	// Expected protocol values
	SPDM_SpdmVersion11                      = 0x11
	SPDM_REQUEST_SpdmReqCodeGetMeasurements = 224
	SPDM_RESPONSE_SpdmReqCodeMeasurements   = 0x60

	SPDM_RESPONSE_kSpdmVersionSize             = 1  ///< Size of SPDMVersion field in bytes.
	SPDM_RESPONSE_kRequestResponseCodeSize     = 1  ///< Size of RequestResponseCode field in bytes.
	SPDM_RESPONSE_kParam1Size                  = 1  ///< Size of Param1 field in bytes.
	SPDM_RESPONSE_kParam2Size                  = 1  ///< Size of Param2 field in bytes.
	SPDM_RESPONSE_kNumberOfBlocksSize          = 1  ///< Size of NumberOfBlocks field in bytes.
	SPDM_RESPONSE_kMeasurementRecordLengthSize = 3  ///< Size of MeasurementRecordLength field in bytes.
	SPDM_RESPONSE_kNonceSize                   = 32 ///< Size of Nonce field in bytes.
	SPDM_RESPONSE_kOpaqueLengthSize            = 2  ///< Size of OpaqueLength field in bytes.
	SPDM_RESPONSE_OpaqueDataTypeSize           = 2
	SPDM_RESPONSE_DATA_SIZE_FIELD_SIZE         = 2
)

type SpdmMeasurementRequestMessage11 struct {
	spdmVersion         uint8
	requestResponseCode uint8
	param1              uint8
	param2              uint8
	nonce               [SPDM_REQUEST_NonceSize]uint8
	slotIDParam         uint8
}

var (
	ErrSpdmParseError     = errors.New("SPDM parse error")
	ErrGpuEvidenceInvalid = errors.New("GPU evidence invalid")
	ErrInternalError      = errors.New("internal error")
)

// ParsedOpaqueField represents an individual data payload found inside the OpaqueData block
type ParsedOpaqueField struct {
	DataType GpuOpaqueDataType
	Data     []byte
}

type SpdmMeasurementResponse struct {
	SpdmVersion             uint8
	RequestResponseCode     uint8
	Param1                  uint8
	Param2                  uint8
	NumberOfBlocks          uint8
	MeasurementRecordLength uint32
	MeasurementRecordData   []byte
	Nonce                   [SPDM_RESPONSE_kNonceSize]uint8
	OpaqueDataLength        uint16
	OpaqueFields            []ParsedOpaqueField
	Signature               []byte
}

func GetSPDMOpaqueFieldOfType(resp *SpdmMeasurementResponse, t GpuOpaqueDataType) []byte {
	for _, r := range (*resp).OpaqueFields {
		if r.DataType == t {
			return r.Data
		}
	}
	return nil
}

func CreateSpdmMeasurementResponseMessage11(responseData []byte, signatureLength int) (*SpdmMeasurementResponse, error) {
	currentOffset := 0
	responseDataLen := len(responseData)
	res := &SpdmMeasurementResponse{}

	// 1. SPDMVersion (1 byte)
	if currentOffset+SPDM_RESPONSE_kSpdmVersionSize > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.SpdmVersion = responseData[currentOffset]
	if res.SpdmVersion != SPDM_SpdmVersion11 {
		log.Debugf("SPDMVersion is not 0x%X (1.1). Actual version: 0x%X", SPDM_SpdmVersion11, res.SpdmVersion)
		return nil, ErrSpdmParseError
	}
	currentOffset += SPDM_RESPONSE_kSpdmVersionSize

	// 2. RequestResponseCode (1 byte)
	if currentOffset+SPDM_RESPONSE_kRequestResponseCodeSize > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.RequestResponseCode = responseData[currentOffset]
	if res.RequestResponseCode != SPDM_RESPONSE_SpdmReqCodeMeasurements {
		log.Debugf("RequestResponseCode is not 0x%X (MEASUREMENTS). Actual code: 0x%X", SPDM_REQUEST_SpdmReqCodeGetMeasurements, res.RequestResponseCode)
		return nil, ErrSpdmParseError
	}
	currentOffset += SPDM_RESPONSE_kRequestResponseCodeSize

	// 3. Param1 (1 byte)
	if currentOffset+SPDM_RESPONSE_kParam1Size > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.Param1 = responseData[currentOffset]
	currentOffset += SPDM_RESPONSE_kParam1Size

	// 4. Param2 (1 byte)
	if currentOffset+SPDM_RESPONSE_kParam2Size > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.Param2 = responseData[currentOffset]
	currentOffset += SPDM_RESPONSE_kParam2Size

	// 5. NumberOfBlocks (1 byte)
	if currentOffset+SPDM_RESPONSE_kNumberOfBlocksSize > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.NumberOfBlocks = responseData[currentOffset]
	currentOffset += SPDM_RESPONSE_kNumberOfBlocksSize

	if res.NumberOfBlocks == 0 {
		log.Debug("NumberOfBlocks is 0. This is not a valid SPDM GET_MEASUREMENTS response.")
		return nil, ErrSpdmParseError
	}

	// 6. MeasurementRecordLength (3 bytes, little-endian)
	if currentOffset+SPDM_RESPONSE_kMeasurementRecordLengthSize > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.MeasurementRecordLength = uint32(responseData[currentOffset]) |
		uint32(responseData[currentOffset+1])<<8 |
		uint32(responseData[currentOffset+2])<<16
	currentOffset += SPDM_RESPONSE_kMeasurementRecordLengthSize

	// 7. MeasurementRecord (variable length)
	recordLen := int(res.MeasurementRecordLength)
	if currentOffset+recordLen > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.MeasurementRecordData = make([]byte, recordLen)
	copy(res.MeasurementRecordData, responseData[currentOffset:currentOffset+recordLen])
	currentOffset += recordLen

	// 8. Nonce (32 bytes)
	if currentOffset+SPDM_RESPONSE_kNonceSize > responseDataLen {
		return nil, ErrSpdmParseError
	}
	copy(res.Nonce[:], responseData[currentOffset:currentOffset+SPDM_RESPONSE_kNonceSize])
	currentOffset += SPDM_RESPONSE_kNonceSize

	// 9. OpaqueLength (2 bytes, little-endian)
	if currentOffset+SPDM_RESPONSE_kOpaqueLengthSize > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.OpaqueDataLength = binary.LittleEndian.Uint16(responseData[currentOffset : currentOffset+SPDM_RESPONSE_kOpaqueLengthSize])
	currentOffset += SPDM_RESPONSE_kOpaqueLengthSize

	// 10. OpaqueData (variable length parsing block)
	opaqueLen := int(res.OpaqueDataLength)
	if currentOffset+opaqueLen > responseDataLen {
		return nil, ErrSpdmParseError
	}
	log.Tracef("OpaqueLen = %d\n", opaqueLen)
	if opaqueLen == 0 {
		log.Errorf("OpaqueData is empty but is required for SPDM GET_MEASUREMENTS response.")
		return nil, ErrSpdmParseError
	}

	// Capture the bounded slice for Opaque Data parsing loops
	opaqueDataSlice := responseData[currentOffset : currentOffset+opaqueLen]
	currentOffset += opaqueLen

	opaqueOffset := 0
	res.OpaqueFields = make([]ParsedOpaqueField, 0)

	for opaqueOffset < len(opaqueDataSlice) {
		// Read DataType (2 bytes, LE)
		if opaqueOffset+SPDM_RESPONSE_OpaqueDataTypeSize > len(opaqueDataSlice) {
			return nil, ErrSpdmParseError
		}
		dataTypeValRaw := binary.LittleEndian.Uint16(opaqueDataSlice[opaqueOffset : opaqueOffset+SPDM_RESPONSE_DATA_SIZE_FIELD_SIZE])
		opaqueOffset += SPDM_RESPONSE_OpaqueDataTypeSize

		// Read DataSize (2 bytes, LE)
		if opaqueOffset+SPDM_RESPONSE_DATA_SIZE_FIELD_SIZE > len(opaqueDataSlice) {
			return nil, ErrSpdmParseError
		}
		dataSize := binary.LittleEndian.Uint16(opaqueDataSlice[opaqueOffset : opaqueOffset+SPDM_RESPONSE_DATA_SIZE_FIELD_SIZE])
		opaqueOffset += SPDM_RESPONSE_DATA_SIZE_FIELD_SIZE

		// Read Value Data Slices
		dataSizeIdx := int(dataSize)
		if opaqueOffset+dataSizeIdx > len(opaqueDataSlice) {
			return nil, ErrSpdmParseError
		}
		valueBytes := make([]byte, dataSizeIdx)
		copy(valueBytes, opaqueDataSlice[opaqueOffset:opaqueOffset+dataSizeIdx])
		opaqueOffset += dataSizeIdx

		res.OpaqueFields = append(res.OpaqueFields, ParsedOpaqueField{
			DataType: GpuOpaqueDataType(dataTypeValRaw),
			Data:     valueBytes,
		})
	}

	if opaqueOffset != len(opaqueDataSlice) {
		log.Errorf("OpaqueData has %d trailing bytes after parsing.\n", len(opaqueDataSlice)-opaqueOffset)
		return nil, ErrInternalError
	}

	// 11. Signature (variable length)
	if currentOffset+signatureLength > responseDataLen {
		return nil, ErrSpdmParseError
	}
	res.Signature = make([]byte, signatureLength)
	copy(res.Signature, responseData[currentOffset:currentOffset+signatureLength])
	currentOffset += signatureLength

	// 12. Final trailing byte verification
	if currentOffset != responseDataLen {
		log.Errorf("SPDM GET_MEASUREMENTS response has %d trailing bytes.\n", responseDataLen-currentOffset)
		return nil, ErrSpdmParseError
	}
	log.Tracef("No trailing bytes...\n")
	return res, nil
}

func GetVBIOSVersion(vbiosVersionData []byte) (string, error) {
	if len(vbiosVersionData) == 0 {
		return "", errors.New("empty VBIOS data")
	}

	// 1. Reverse the byte slice
	// We copy the data first to avoid mutating the original input slice
	reversedData := make([]byte, len(vbiosVersionData))
	for i, j := 0, len(vbiosVersionData)-1; j >= 0; i, j = i+1, j-1 {
		reversedData[i] = vbiosVersionData[j]
	}

	// 2. Convert to a hex string
	hexValue := hex.EncodeToString(reversedData)

	// 3. Re-arrange the hex string (preserving the original C++ logic)
	// "why is this done? if someone ever finds out, pls update this comment"
	hexLen := len(hexValue)
	halfLen := hexLen / 2

	if halfLen < 2 {
		return "", errors.New("hex string too short for slicing logic")
	}

	secondHalf := hexValue[halfLen:]
	beforeMiddle := hexValue[halfLen-2 : halfLen]
	temp := secondHalf + beforeMiddle

	// 4. Format as XX.XX.XX.XX.XX by taking pairs and adding dots
	var pairs []string
	for i := 0; i < len(temp); i += 2 {
		// Guard against odd lengths to prevent out-of-bounds slicing
		if i+2 <= len(temp) {
			pairs = append(pairs, temp[i:i+2])
		}
	}
	result := strings.Join(pairs, ".")

	// 5. Convert to uppercase
	result = strings.ToUpper(result)

	// 6. Remove null terminators (and any trailing dots that might result)
	result = strings.ReplaceAll(result, "\x00", "")
	result = strings.Trim(result, ".")

	return result, nil
}

func (resp SpdmMeasurementResponse) getVbiosVersion() (string, error) {
	for _, field := range resp.OpaqueFields {
		if field.DataType == GpuOpaqueDataTypeVbiosVersion {
			return GetVBIOSVersion(field.Data)
		}
	}
	log.Debugf("Field vbios version not found!")
	return "", errors.New("no vbios field in evidence")
}

func (resp SpdmMeasurementResponse) getDriverVersion() (string, error) {
	for _, field := range resp.OpaqueFields {
		if field.DataType == GpuOpaqueDataTypeDriverVersion {
			return strings.Trim(string(field.Data), " \t\n\r\x00"), nil
		}
	}
	log.Debugf("Field driver version not found!")
	return "", errors.New("no driver field in evidence")
}

func CreateSpdmMeasurementRequestMessage11(requestData []byte) (*SpdmMeasurementRequestMessage11, error) {
	msg := &SpdmMeasurementRequestMessage11{}
	err := msg.parse(requestData)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (m *SpdmMeasurementRequestMessage11) parse(requestData []byte) error {
	// Strict size check validation
	if len(requestData) != SPDM_REQUEST_kRequestLength {
		log.Debug("SPDM Measurement Request Message11: Invalid request data size")
		return ErrSpdmParseError
	}

	offset := 0

	// 1. Parse & validate SPDM Version
	m.spdmVersion = requestData[offset]
	offset += SPDM_REQUEST_SpdmVersionSize
	if m.spdmVersion != SPDM_SpdmVersion11 {
		log.Debugf("SPDMVersion is not 0x%X (1.1). Actual version: 0x%x", SPDM_SpdmVersion11, m.spdmVersion)
		return ErrSpdmParseError
	}

	// 2. Parse & validate Request Response Code
	m.requestResponseCode = requestData[offset]
	offset += SPDM_REQUEST_RequestResponseCodeSize
	if m.requestResponseCode != SPDM_REQUEST_SpdmReqCodeGetMeasurements {
		log.Debugf("RequestResponseCode is not 0x%X (GET_MEASUREMENTS). Actual code: 0x%x",
			SPDM_REQUEST_SpdmReqCodeGetMeasurements, m.requestResponseCode)
		return ErrSpdmParseError
	}

	// 3. Parse Param1
	m.param1 = requestData[offset]
	offset += SPDM_REQUEST_Param1Size

	// 4. Parse Param2
	m.param2 = requestData[offset]
	offset += SPDM_REQUEST_Param2Size

	// 5. Parse Nonce (checkedCopyN replication)
	copy(m.nonce[:], requestData[offset:offset+SPDM_REQUEST_NonceSize])
	offset += SPDM_REQUEST_NonceSize

	// 6. Parse SlotIDParam
	m.slotIDParam = requestData[offset]
	offset += SPDM_REQUEST_SlotIDParamSize

	// 7. Final trailing bytes verification
	if offset != SPDM_REQUEST_kRequestLength {
		log.Debug("Trailing bytes after parsing in SPDM Measurement Request Message11")
		return ErrSpdmParseError
	}

	return nil
}

func (r *SpdmMeasurementResponse) String() string {
	out := fmt.Sprintf(
		"SpdmMeasurementResponse{\n"+
			"  SpdmVersion:             0x%02X,\n"+
			"  RequestResponseCode:     0x%02X,\n"+
			"  Param1:                  0x%02X,\n"+
			"  Param2:                  0x%02X,\n"+
			"  NumberOfBlocks:          %d,\n"+
			"  MeasurementRecordLength: %d bytes,\n"+
			"  Nonce:                   0x%X,\n"+
			"  OpaqueDataLength:        %d bytes,\n"+
			"  OpaqueFields:\n",
		r.SpdmVersion, r.RequestResponseCode, r.Param1, r.Param2, r.NumberOfBlocks, r.MeasurementRecordLength, r.Nonce, r.OpaqueDataLength,
	)
	for i, f := range r.OpaqueFields {
		out += fmt.Sprintf("    [%d] Type: 0x%04X (= %s), Len: %d, Data: 0x%X\n", i, uint16(f.DataType), f.DataType.String(), len(f.Data), f.Data)
	}
	out += fmt.Sprintf("  Signature (%d bytes): 0x%X\n}", len(r.Signature), r.Signature)
	return out
}

func (m *SpdmMeasurementRequestMessage11) String() string {
	return fmt.Sprintf(
		"SpdmMeasurementRequestMessage11{\n"+
			"  SPDMVersion:         0x%02X,\n"+
			"  RequestResponseCode: 0x%02X,\n"+
			"  Param1:              0x%02X,\n"+
			"  Param2:              0x%02X,\n"+
			"  Nonce:               0x%X,\n"+
			"  SlotIDParam:         0x%02X\n"+
			"}",
		m.spdmVersion,
		m.requestResponseCode,
		m.param1,
		m.param2,
		m.nonce,
		m.slotIDParam,
	)
}

type MeasurementValueType uint8

const (
	MVTImmutableROM        MeasurementValueType = 0x00
	MVTMutableFirmware     MeasurementValueType = 0x01
	MVTHardwareConfig      MeasurementValueType = 0x02
	MVTFirmwareConfig      MeasurementValueType = 0x03
	MVTMeasurementManifest MeasurementValueType = 0x04
	// 0x05–0x08 reserved by DMTF; NVIDIA uses some vendor values beyond that
)

func (t MeasurementValueType) String() string {
	switch t {
	case MVTImmutableROM:
		return "ImmutableROM"
	case MVTMutableFirmware:
		return "MutableFirmware"
	case MVTHardwareConfig:
		return "HardwareConfig"
	case MVTFirmwareConfig:
		return "FirmwareConfig"
	case MVTMeasurementManifest:
		return "MeasurementManifest"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", uint8(t))
	}
}

// ─── Parsed structures ────────────────────────────────────────────────────────────────────────────

// MeasurementBlock is one entry inside a MeasurementRecord.
// Wire layout (SPDM 1.1, DMTF spec §10.11):
//
//	Offset  Size  Field
//	0       1     Index
//	1       1     MeasurementSpecification  (0x01 = DMTF)
//	2       2     MeasurementSize           (LE, covers the DMTF header + Value)
//	---- DMTF Measurement header (inside the above MeasurementSize bytes) ----
//	4       1     DMTFSpecMeasurementValueType
//	               bit 7: 0 = digest, 1 = raw bitstream
//	               bits [6:0]: type enum above
//	5       2     DMTFSpecMeasurementValueSize  (LE, length of Value)
//	7       N     Value  (digest or raw blob)
type MeasurementBlock struct {
	Index     uint8
	MeasSpec  uint8
	IsDigest  bool
	ValueType MeasurementValueType
	Value     []byte
}

func (b *MeasurementBlock) Dump(i int) {
	form := "digest"
	if !b.IsDigest {
		form = "raw bitstream"
	}
	log.Tracef("  [block %d]\n", i)
	log.Tracef("    Index      : %d  (matches RIM <Resource index=\"%d\">)\n", b.Index, b.Index)
	log.Tracef("    MeasSpec   : 0x%02x  (%s)\n", b.MeasSpec, measSpecName(b.MeasSpec))
	log.Tracef("    ValueType  : %s  (%s)\n", b.ValueType, form)
	log.Tracef("    ValueSize  : %d bytes\n", len(b.Value))
	log.Tracef("    Value      : %s\n", hexWrap(b.Value, 12))
	log.Traceln()
}

func measSpecName(s uint8) string {
	if s == 0x01 {
		return "DMTF"
	}
	return "unknown"
}

func ParseMeasurementRecord(data []byte) ([]*MeasurementBlock, error) {
	var blocks []*MeasurementBlock
	pos := 0

	for pos < len(data) {
		remaining := len(data) - pos

		// Need at least the 4-byte common header.
		if remaining < 4 {
			return nil, fmt.Errorf("short record at offset %d: %d bytes left, need 4 for common header", pos, remaining)
		}

		index := data[pos]
		measSpec := data[pos+1]
		measSize := int(binary.LittleEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if measSize < 3 {
			return nil, fmt.Errorf("block at index %d has MeasurementSize=%d, need at least 3 for DMTF header", index, measSize)
		}
		if pos+measSize > len(data) {
			return nil, fmt.Errorf("block at index %d claims MeasurementSize=%d but only %d bytes remain", index, measSize, len(data)-pos)
		}

		// DMTF Measurement header is the first 3 bytes of the measurement payload.
		rawType := data[pos]
		isDigest := (rawType & 0x80) == 0 // bit 7 = 0 → digest
		valueType := MeasurementValueType(rawType & 0x7F)
		valueSize := int(binary.LittleEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		expectedValueSize := measSize - 3
		if valueSize != expectedValueSize {
			return nil, fmt.Errorf(
				"block index %d: DMTFSpecMeasurementValueSize=%d but MeasurementSize-3=%d",
				index, valueSize, expectedValueSize,
			)
		}
		if pos+valueSize > len(data) {
			return nil, fmt.Errorf("block index %d: value of size %d overruns buffer", index, valueSize)
		}

		value := make([]byte, valueSize)
		copy(value, data[pos:pos+valueSize])
		pos += valueSize

		blocks = append(blocks, &MeasurementBlock{
			Index:     index,
			MeasSpec:  measSpec,
			IsDigest:  isDigest,
			ValueType: valueType,
			Value:     value,
		})
	}

	return blocks, nil
}

func hexWrap(b []byte, indent int) string {
	if len(b) == 0 {
		return "(empty)"
	}
	h := hex.EncodeToString(b)
	var sb strings.Builder
	pad := strings.Repeat(" ", indent)
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			if (i/2)%16 == 0 {
				sb.WriteString("\n")
				sb.WriteString(pad)
			} else {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}
