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

package tpmdriver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// Constants for digests and TCG Events
const (
	SHA1_DIGEST_LEN    = 20
	SHA256_DIGEST_LEN  = 32
	SHA384_DIGEST_LEN  = 48
	SHA512_DIGEST_LEN  = 64
	SM3_256_DIGEST_LEN = 32
	MAX_TCG_EVENT_LEN  = 1024
)

// Constants
var (
	// ASCII String Spec ID Event03
	SPEC_ID_SIGNATURE          = [16]byte{0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x00}
	STARTUP_LOCALITY_SIGNATURE = [16]byte{0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x4C, 0x6F, 0x63, 0x61, 0x6C, 0x69, 0x74, 0x79, 0x00}
	EV_PREBOOT_CERT            = uint32(0)
	EV_POST_CODE               = uint32(1)
	EV_UNUSED                  = uint32(2)
	EV_NO_ACTION               = uint32(3)
	EV_SEPARATOR               = uint32(4)
	EV_ACTION                  = uint32(5)
	EV_EVENT_TAG               = uint32(6)
	EV_S_CRTM_CONTENTS         = uint32(7)
	EV_S_CRTM_VERSION          = uint32(8)
	EV_CPU_MICROCODE           = uint32(9)
	EV_PLATFORM_CONFIG_FLAGS   = uint32(10)
	EV_TABLE_OF_DEVICES        = uint32(11)
	EV_COMPACT_HASH            = uint32(12)
	EV_IPL                     = uint32(13)
	EV_IPL_PARTITION_DATA      = uint32(14)
	EV_NONHOST_CODE            = uint32(15)
	EV_NONHOST_CONFIG          = uint32(16)
	EV_NONHOST_INFO            = uint32(17)
	EV_OMIT_BOOT_DEVICE_EVENTS = uint32(18)
	EV_POST_CODE2              = uint32(19)

	EV_EFI_EVENT_BASE                = uint32(0x80000000)
	EV_EFI_VARIABLE_DRIVER_CONFIG    = uint32(0x80000001)
	EV_EFI_VARIABLE_BOOT             = uint32(0x80000002)
	EV_EFI_BOOT_SERVICES_APPLICATION = uint32(0x80000003)
	EV_EFI_BOOT_SERVICES_DRIVER      = uint32(0x80000004)
	EV_EFI_RUNTIME_SERVICES_DRIVER   = uint32(0x80000005)
	EV_EFI_GPT_EVENT                 = uint32(0x80000006)
	EV_EFI_ACTION                    = uint32(0x80000007)
	EV_EFI_PLATFORM_FIRMWARE_BLOB    = uint32(0x80000008)
	EV_EFI_HANDOFF_TABLES            = uint32(0x80000009)
	EV_EFI_PLATFORM_FIRMWARE_BLOB2   = uint32(0x8000000a)
	EV_EFI_HANDOFF_TABLES2           = uint32(0x8000000b)
	EV_EFI_VARIABLE_BOOT2            = uint32(0x8000000c)
	EV_EFI_GPT_EVENT2                = uint32(0x8000000d)

	EV_EFI_HCRTM_EVENT = uint32(0x80000010)

	EV_EFI_VARIABLE_AUTHORITY    = uint32(0x800000E0)
	EV_EFI_SPDM_FIRMWARE_BLOB    = uint32(0x800000e1)
	EV_EFI_SPDM_FIRMWARE_CONFIG  = uint32(0x800000e2)
	EV_EFI_SPDM_DEVICE_POLICY    = uint32(0x800000e3)
	EV_EFI_SPDM_DEVICE_AUTHORITY = uint32(0x800000e4)
)

// TPM2B_EVENT is a TPM event as specified by the TPM specificatoin
type TPM2B_EVENT struct {
	Size uint16
	Buf  []byte
}

// TCG_EVENT represents the TCG_PCR_EVENT as specified in TCG PC Client Platform Firmware
// Profile Specification
type TCG_EVENT struct {
	PcrIndex      uint32
	EventType     uint32
	Digest        [20]byte
	EventDataSize uint32
}

// TCG_EVENT2 represents the TCG_PCR_EVENT2 as specified in TCG PC Client Platform Firmware
// Profile Specification
type TCG_EVENT2 struct {
	PcrIndex           uint32
	EventType          uint32
	TPML_DIGEST_VALUES []byte
	EventDataSize      uint32
}

// TPML_DIGEST_VALUES are a List of digests extended to PCRIndex
type TPML_DIGEST_VALUES struct {
	Count   uint32
	Digests []TPMT_HA
}

type TPMT_HA struct {
	AlgorithmId uint16
	Digest      []uint8
}

// TCG_EfiSpecIdEvent partially represents the TCG_EfiSpecIdEvent as specified in
// TCG PC Client Platform Firmware Profile Specification
type TCG_EfiSpecIdEvent struct {
	Signature          [16]byte // "Spec ID Event03\x00"
	PlatformClass      uint32
	FamilyVersionMinor uint8
	FamilyVersionMajor uint8
	SpecRevision       uint8
	UintnSize          uint8 // 1 = uint32, 2 = uint64
	NumberOfAlgorithms uint32
}

type TCG_AlgorithmSize struct {
	AlgorithmId uint16 // TPMI_ALG_HASH
	DigestSize  uint16
}

func GetBiosArtifacts(file, refvalType string, addRawEventData bool) (map[int]ar.Artifact, error) {

	// Get single events
	refvals, err := GetBiosMeasurements(file, refvalType, addRawEventData)
	if err != nil {
		return nil, err
	}

	// Map with PCR index as key
	artifacts := map[int]ar.Artifact{}

	// Convert to artifacts
	for _, refval := range refvals {

		artifact, ok := artifacts[refval.Index]
		if !ok {
			artifact = ar.Artifact{
				Type:  ar.TYPE_PCR_EVENTLOG,
				Index: int(refval.Index),
			}
		}
		event := ar.MeasureEvent{
			Sha256:    refval.Sha256,
			EventName: refval.SubType,
		}
		if refval.SubType != "TPM_PCR_INIT_VALUE" {
			event.EventData = refval.EventData
		}
		artifact.Events = append(artifact.Events, event)
		artifacts[refval.Index] = artifact
	}

	return artifacts, nil
}

// GetBiosMeasurements retrieves the measurements recorded into the TPM PCRs by BIOS, UEFI and IPL.
// The file with the binary measurements (e.g., /sys/kernel/security/tpm0/binary_bios_measurements)
// must be specified
func GetBiosMeasurements(file, refvalType string, addRawEventData bool) ([]ar.ReferenceValue, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	digests, err := parseBiosMeasurements(data, refvalType, addRawEventData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse binary bios measurements event log: %w", err)
	}

	return digests, nil
}

func parseBiosMeasurements(data []byte, refvalType string, addRawEventData bool) ([]ar.ReferenceValue, error) {

	buf := bytes.NewBuffer(data)

	// Read initial TCG Event to detect event log format
	var event TCG_EVENT
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return nil, fmt.Errorf("failed to read initial binary data: %w", err)
	}

	// Determine the event log version
	log.Tracef("Initial Event Type: %v", eventtypeToString(event.EventType))

	if event.EventType == EV_NO_ACTION {
		// Eventlog format version 2 or later starts with EV_NO_ACTION event
		specIdBuf := bytes.NewBuffer(buf.Bytes())
		var specIdEvent TCG_EfiSpecIdEvent
		err = binary.Read(specIdBuf, binary.LittleEndian, &specIdEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to parse initial TCG spec ID event: %w", err)
		}

		//skips the data event entries of the EV_NO_ACTION event
		buf.Next(int(event.EventDataSize))

		// Detect the version
		switch specIdEvent.FamilyVersionMajor {
		case 2:
			log.Trace("Detected event log format version 2")
			return parseBiosMeasurementsV2(buf.Bytes(), refvalType, addRawEventData)
		default:
			return nil, fmt.Errorf("unsuported Eventlog version %v.%v", specIdEvent.FamilyVersionMajor,
				specIdEvent.FamilyVersionMinor)
		}
	} else {
		// Eventlog format version 1 directly starts with extended events
		log.Trace("Detected event log format version 1")
		return parseBiosMeasurementsV1(data, refvalType)
	}
}

func parseBiosMeasurementsV1(data []byte, refvalType string) ([]ar.ReferenceValue, error) {

	buf := bytes.NewBuffer(data)
	extends := make([]ar.ReferenceValue, 0)

	// An entry is at least 32 Bytes long
	for buf.Len() >= 32 {

		var event TCG_EVENT
		err := binary.Read(buf, binary.LittleEndian, &event)
		if err != nil {
			return nil, fmt.Errorf("failed to read initial binary data: %w", err)
		}

		// Skip the event data
		buf.Next(int(event.EventDataSize))

		//add to extends
		extends = append(extends, ar.ReferenceValue{
			Type:    refvalType,
			Index:   int(event.PcrIndex),
			Sha1:    event.Digest[:],
			SubType: eventtypeToString(event.EventType),
		})
	}

	return extends, nil

}

func parseBiosMeasurementsV2(data []byte, refvalType string, addRawEventData bool) ([]ar.ReferenceValue, error) {

	buf := bytes.NewBuffer(data)
	extends := make([]ar.ReferenceValue, 0)
	initializedPCR := make([]bool, 24) //bool array track of what pcrs have been initialized

	// An entry is at least 16 Bytes long
	for buf.Len() >= 16 {

		// Reading the first PCR entry
		var pcrIndex, eventType, digestCount uint32
		// var pcrIndex int
		binary.Read(buf, binary.LittleEndian, &pcrIndex)
		binary.Read(buf, binary.LittleEndian, &eventType)
		eventName := eventtypeToString(eventType)
		binary.Read(buf, binary.LittleEndian, &digestCount)

		var digestAlgorithmID uint16
		var sha256Digest ar.HexByte
		var sha384Digest ar.HexByte
		for i := 0; i < int(digestCount); i++ {
			binary.Read(buf, binary.LittleEndian, &digestAlgorithmID)
			digestLength, err := algorithmIDtoSize(digestAlgorithmID)
			if err != nil {
				return nil, err
			}
			if int(digestLength)+4 > buf.Len() {
				return nil, errors.New("not enough remaining bytes in buffer")
			}
			digest := make(ar.HexByte, digestLength)
			binary.Read(buf, binary.LittleEndian, &digest)
			switch digestAlgorithmID {
			case 0x000b: //sha256
				sha256Digest = make(ar.HexByte, SHA256_DIGEST_LEN)
				copy(sha256Digest, digest)
			case 0x000c: //sha384
				sha384Digest = make(ar.HexByte, SHA384_DIGEST_LEN)
				copy(sha384Digest, digest)
			}
			//other digest types will be implicitly skipped
		}
		var eventSize uint32
		binary.Read(buf, binary.LittleEndian, &eventSize)
		if int(eventSize) > buf.Len() {
			return nil, errors.New("not enough remaining bytes in buffer")
		}

		//data to include in the ReferenceValues
		var extendedeventData *ar.EventData

		//bytes of the event should be added to the array
		eventData := make([]uint8, eventSize)
		binary.Read(buf, binary.LittleEndian, &eventData)
		var eventDataRaw []byte
		copy(eventDataRaw, eventData)

		parseEvent := true

		//checks for locality
		if pcrIndex > 24 {
			log.Errorf("Invalid PCR: %v", pcrIndex)
		}
		//pcr value has not been initialized
		if !initializedPCR[pcrIndex] {
			//generate the locality entry
			entry, skipEvent, err := generateLocalityEntry(int(pcrIndex), eventType, eventData)
			if err != nil {
				log.Debug(err)
			} else {
				extends = append(extends, entry)
			}
			parseEvent = !skipEvent
			initializedPCR[pcrIndex] = true

		}
		if parseEvent {
			extendedeventData = ar.ParseEventData(eventData, eventName, addRawEventData)
		}

		//either Sha256 or Sha384 must be present
		if !(len(sha384Digest) == SHA384_DIGEST_LEN || len(sha256Digest) == SHA256_DIGEST_LEN) {
			return nil, errors.New("no SHA256 or SHA384 in TCG event entry")
		}

		//skip event
		if eventName == eventtypeToString(EV_NO_ACTION) {
			continue
		}

		//add to extends
		extends = append(extends, ar.ReferenceValue{
			Type:      refvalType,
			Index:     int(pcrIndex),
			Sha256:    sha256Digest,
			Sha384:    sha384Digest,
			SubType:   eventName,
			EventData: extendedeventData,
		})
	}

	return extends, nil
}

func generateLocalityEntry(pcrIndex int, eventType uint32, eventData []uint8) (ar.ReferenceValue, bool, error) {
	var found_hcrtm bool
	var locality byte
	skipEvent := false
	eventD := bytes.NewBuffer(eventData)

	if pcrIndex == 0 {
		if eventType == EV_EFI_HCRTM_EVENT {
			found_hcrtm = true
			locality = 0x04 //startup locality shall be set to 0x04 if a H-CRTM event was found
		}

		/* Handle StartupLocality in replay for PCR0 */
		if !found_hcrtm && eventType == EV_NO_ACTION && pcrIndex == 0 {
			if eventD.Len() < 17 { // sizeof(EV_NO_ACTION_STRUCT))
				return ar.ReferenceValue{}, false, errors.New("eventsize is too small")
			}

			signature := eventD.Next(16)

			if bytes.Equal(signature, STARTUP_LOCALITY_SIGNATURE[:]) {

				locality = eventD.Next(1)[0]
				skipEvent = true
			}
		}
	}

	digest := make([]byte, 32)
	digest[31] = locality

	entry := ar.ReferenceValue{
		Type:    ar.TYPE_REFVAL_TPM,
		Sha256:  digest,
		SubType: "TPM_PCR_INIT_VALUE",
		Index:   pcrIndex,
	}

	//generate the Locality
	return entry, skipEvent, nil
}

// switch for the event types
func eventtypeToString(event_type uint32) string {
	switch event_type {
	case EV_PREBOOT_CERT:
		return "EV_PREBOOT_CERT"
	case EV_POST_CODE:
		return "EV_POST_CODE"
	case EV_UNUSED:
		return "EV_UNUSED"
	case EV_NO_ACTION:
		return "EV_NO_ACTION"
	case EV_SEPARATOR:
		return "EV_SEPARATOR"
	case EV_ACTION:
		return "EV_ACTION"
	case EV_EVENT_TAG:
		return "EV_EVENT_TAG"
	case EV_S_CRTM_CONTENTS:
		return "EV_S_CRTM_CONTENTS"
	case EV_S_CRTM_VERSION:
		return "EV_S_CRTM_VERSION"
	case EV_CPU_MICROCODE:
		return "EV_CPU_MICROCODE"
	case EV_PLATFORM_CONFIG_FLAGS:
		return "EV_PLATFORM_CONFIG_FLAGS"
	case EV_TABLE_OF_DEVICES:
		return "EV_TABLE_OF_DEVICES"
	case EV_COMPACT_HASH:
		return "EV_COMPACT_HASH"
	case EV_IPL:
		return "EV_IPL"
	case EV_IPL_PARTITION_DATA:
		return "EV_IPL_PARTITION_DATA"
	case EV_NONHOST_CODE:
		return "EV_NONHOST_CODE"
	case EV_NONHOST_CONFIG:
		return "EV_NONHOST_CONFIG"
	case EV_NONHOST_INFO:
		return "EV_NONHOST_INFO"
	case EV_OMIT_BOOT_DEVICE_EVENTS:
		return "EV_OMIT_BOOT_DEVICE_EVENTS"
	case EV_POST_CODE2:
		return "EV_POST_CODE2"
	case EV_EFI_EVENT_BASE:
		return "EV_EFI_HCRTM_EVENT"
	case EV_EFI_VARIABLE_DRIVER_CONFIG:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case EV_EFI_VARIABLE_BOOT:
		return "EV_EFI_VARIABLE_BOOT"
	case EV_EFI_BOOT_SERVICES_APPLICATION:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case EV_EFI_BOOT_SERVICES_DRIVER:
		return "EV_EFI_BOOT_SERVICES_DRIVER"
	case EV_EFI_RUNTIME_SERVICES_DRIVER:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER"
	case EV_EFI_GPT_EVENT:
		return "EV_EFI_GPT_EVENT"
	case EV_EFI_ACTION:
		return "EV_EFI_ACTION"
	case EV_EFI_PLATFORM_FIRMWARE_BLOB:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB"
	case EV_EFI_HANDOFF_TABLES:
		return "EV_EFI_HANDOFF_TABLES"
	case EV_EFI_PLATFORM_FIRMWARE_BLOB2:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
	case EV_EFI_HANDOFF_TABLES2:
		return "EV_EFI_HANDOFF_TABLES2"
	case EV_EFI_VARIABLE_BOOT2:
		return "EV_EFI_VARIABLE_BOOT2"
	case EV_EFI_GPT_EVENT2:
		return "EV_EFI_GPT_EVENT2"
	case EV_EFI_HCRTM_EVENT:
		return "EV_EFI_HCRTM_EVENT"
	case EV_EFI_VARIABLE_AUTHORITY:
		return "EV_EFI_VARIABLE_AUTHORITY"
	case EV_EFI_SPDM_FIRMWARE_BLOB:
		return "EV_EFI_SPDM_FIRMWARE_BLOB"
	case EV_EFI_SPDM_FIRMWARE_CONFIG:
		return "EV_EFI_SPDM_FIRMWARE_CONFIG"
	case EV_EFI_SPDM_DEVICE_POLICY:
		return "EV_EFI_SPDM_DEVICE_POLICY"
	case EV_EFI_SPDM_DEVICE_AUTHORITY:
		return "EV_EFI_SPDM_DEVICE_AUTHORITY"
	default:
		return "Unknown event type"
	}
}

func algorithmIDtoSize(algorithmID uint16) (uint16, error) {
	switch algorithmID {
	case 0x0004:
		return SHA1_DIGEST_LEN, nil
	case 0x000b:
		return SHA256_DIGEST_LEN, nil
	case 0x000c:
		return SHA384_DIGEST_LEN, nil
	case 0x000d:
		return SHA512_DIGEST_LEN, nil
	case 0x0012:
		return SM3_256_DIGEST_LEN, nil
	}
	return 0, fmt.Errorf("unknown Hash Algorithm")
}
