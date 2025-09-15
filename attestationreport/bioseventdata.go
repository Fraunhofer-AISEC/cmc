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

package attestationreport

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

type address uint64

const (
	SHA1_DIGEST_LEN   = 20
	SHA256_DIGEST_LEN = 32
	SHA384_DIGEST_LEN = 48
)

//structs for additional eventlog content --------------------------------

type EventData struct {
	// For certain Uefi variable information events
	Uefivariabledata *UefiVariableData `json:"uefivariabledata,omitempty" cbor:"0,keyasint,omitempty"`

	// For the GPT_Event
	GPTHeader *GPTHeader `json:"gptheader,omitempty" cbor:"1,keyasint,omitempty"`
	// For PCClientTaggedEvent
	PCClientTaggedEvent      *PCClientTaggedEvent      `json:"pcclienttaggedevent,omitempty" cbor:"2,keyasint,omitempty"`
	ImageLoadEvent           *ImageLoadEvent           `json:"imageloadevent,omitempty" cbor:"3,keyasint,omitempty"`
	UefiHandoffTablePointer  *UefiHandoffTablePointer  `json:"uefihandofftablepointer,omitempty" cbor:"4,keyasint,omitempty"`
	UefiPlatformFirmwareBlob *UefiPlatformFirmwareBlob `json:"uefiplatformfirmwareblob,omitempty" cbor:"5,keyasint,omitempty"`
	// Used e.g. for EFI_IPL event
	StringContent string `json:"stringcontent,omitempty" cbor:"6,keyasint,omitempty"`
	// Generic data (when no further differentiation is implemented)
	RawData HexByte `json:"rawdata,omitempty" cbor:"7,keyasint,omitempty"`
}

type UefiVariableData struct {
	VariableNameGUID string `json:"variablenameguid,omitempty" cbor:"0,keyasint,omitempty"`
	UnicodeName      string `json:"unicodename,omitempty" cbor:"1,keyasint,omitempty"`

	//can be one of the following
	Signaturedb       []SignatureDatabase `json:"signaturedb,omitempty" cbor:"2,keyasint,omitempty"`
	BootOrder         []uint16            `json:"bootorder,omitempty" cbor:"3,keyasint,omitempty"`
	BootNext          uint16              `json:"bootnext,omitempty" cbor:"4,keyasint,omitempty"`
	BootCurrent       uint16              `json:"bootcurrent,omitempty" cbor:"5,keyasint,omitempty"`
	BootOptionSupport uint32              `json:"bootoptionsupport,omitempty" cbor:"6,keyasint,omitempty"`
	EFILoadOption     *EFILoadOption      `json:"efiloadoption,omitempty" cbor:"7,keyasint,omitempty"`

	DriverOrder []uint16 `json:"driverorder,omitempty" cbor:"8,keyasint,omitempty"`

	//genericData
	StringContent string  `json:"stringcontent,omitempty" cbor:"9,keyasint,omitempty"`
	VariableData  HexByte `json:"variabledata,omitempty" cbor:"10,keyasint,omitempty"`
	// DevicePath	*FilePathList		`json:"devicepath,omitempty" cbor:"10,keyasint,omitempty"`
	GUIDArray []string `json:"guidarray,omitempty" cbor:"11,keyasint,omitempty"`
}

type SignatureDatabase struct {
	SignatureTypeGUID string `json:"efisignaturelistguid,omitempty" cbor:"0,keyasint,omitempty"`

	SignatureHeader HexByte `json:"signatureheader,omitempty" cbor:"1,keyasint,omitempty"`

	//only one of the following per SignatureDataBase
	Certificates []UEFICertificate `json:"ueficertificates,omitempty" cbor:"2,keyasint,omitempty"`
	Sha256Hash   []Hash            `json:"sha256hashes,omitempty" cbor:"3,keyasint,omitempty"`
}

type UEFICertificate struct {
	SignatureOwnerGUID string            `json:"signatureownerguid" cbor:"0,keyasint"`
	Certificates       X509CertExtracted `json:"certificates" cbor:"1,keyasint"`
}

type Hash struct {
	SignatureOwnerGUID string  `json:"signatureownerguid" cbor:"0,keyasint"`
	Hash               HexByte `json:"hash,omitempty" cbor:"1,keyasint,omitempty"`
}

type EFILoadOption struct {
	Attributes uint32 `json:"attributes" cbor:"0,keyasint"`
	// - could also get resolved to the different options UEFISpec:73
	//-ex filePathListLength uint16
	Description  string         `json:"description" cbor:"1,keyasint"`
	FilepathList []FilePathList `json:"filepathlist" cbor:"2,keyasint"`
	// optional Data
	OptionalData HexByte `json:"optionaldata,omitempty" cbor:"3,keyasint,omitempty"`
}

type FilePathList struct {
	Type    string `json:"type" cbor:"0,keyasint"`
	Subtype string `json:"subtype" cbor:"1,keyasint"`

	//optional stuff
	//     - 2.1 (ACPI Device Path)
	HID HexByte `json:"hid,omitempty" cbor:"2,keyasint,omitempty"`
	UID HexByte `json:"uid,omitempty" cbor:"3,keyasint,omitempty"`

	//     - 3.a (messaging device path: vendor-defined messaging device path)
	VendorGUID        string  `json:"vendorguid,omitempty" cbor:"4,keyasint,omitempty"`
	VendorDefinedData HexByte `json:"vendordefineddata,omitempty" cbor:"4,keyasint,omitempty"`

	//     - 4.1 (media device path: hard drive)
	PartitionNumber    uint32  `json:"partitionnumber,omitempty" cbor:"5,keyasint,omitempty"`
	PartitionStart     uint64  `json:"partitionstart,omitempty" cbor:"6,keyasint,omitempty"`
	PartitionSize      uint64  `json:"partitionsize,omitempty" cbor:"7,keyasint,omitempty"`
	PartitionSignature HexByte `json:"partitionsignature,omitempty" cbor:"8,keyasint,omitempty"` //[16]byte
	PartitionFormat    byte    `json:"partitionformat,omitempty" cbor:"9,keyasint,omitempty"`
	SignaturType       byte    `json:"signaturetype,omitempty" cbor:"10,keyasint,omitempty"`

	//	- 4.2 (media device path: CD-ROM Media Device Path)
	BootEntry uint32 `json:"bootentry,omitempty" cbor:"11,keyasint,omitempty"`
	//PartitionStart
	//PartitionSize

	//	- 4.3 (media device path: Vendor-Defined Media Device Path)
	//VendorGUID
	//VendorDefinedData

	//     - 4.4 (media device path: file path media device path)
	PathName string `json:"pathname,omitempty" cbor:"12,keyasint,omitempty"`

	//     - 4.5 (media device path: Media Protocol Device Path)
	ProtocolGUID string `json:"protocolguid,omitempty" cbor:"13,keyasint,omitempty"`

	//     - 4.9 (media device path: RAM Disk)
	StartingAddress uint64 `json:"startingaddress,omitempty" cbor:"14,keyasint,omitempty"`
	EndingAddress   uint64 `json:"endingaddress,omitempty" cbor:"15,keyasint,omitempty"`
	DiskTypeGUID    string `json:"disktypeguid,omitempty" cbor:"16,keyasint,omitempty"`
	DiskInstance    uint16 `json:"diskinstance,omitempty" cbor:"17,keyasint,omitempty"`

	//	- 5.1 (BIOS Boot Specification Device Path)
	DeviceType        uint16 `json:"devicetype,omitempty" cbor:"18,keyasint,omitempty"`
	StatusFlag        uint16 `json:"statusflag,omitempty" cbor:"19,keyasint,omitempty"`
	DescriptionString string `json:"descriptionstring,omitempty" cbor:"20,keyasint,omitempty"`
}

type GPTHeader struct {
	Signature                uint64              `json:"signature,omitempty" cbor:"0,keyasint,omitempty"`
	Revision                 uint32              `json:"revision,omitempty" cbor:"1,keyasint,omitempty"`
	HeaderSize               uint32              `json:"headersize,omitempty" cbor:"2,keyasint,omitempty"`
	HeaderCRC32              uint32              `json:"headercrc32,omitempty" cbor:"3,keyasint,omitempty"`
	Reserved                 uint32              `json:"reserved,omitempty" cbor:"4,keyasint,omitempty"`
	MyLBA                    uint64              `json:"mylba,omitempty" cbor:"5,keyasint,omitempty"`
	AlternativeLBA           uint64              `json:"alternativelba,omitempty" cbor:"6,keyasint,omitempty"`
	FirstUsableLBA           uint64              `json:"firstusablelba,omitempty" cbor:"7,keyasint,omitempty"`
	LastUsableLBA            uint64              `json:"lastusablelba,omitempty" cbor:"8,keyasint,omitempty"`
	DiskGUID                 string              `json:"diskguid,omitempty" cbor:"9,keyasint,omitempty"`
	PartitionEntryLBA        uint64              `json:"partitionentrylba,omitempty" cbor:"10,keyasint,omitempty"`
	NumberOfPartitionEntries uint32              `json:"numberofpartitionentries,omitempty" cbor:"11,keyasint,omitempty"`
	SizeOfPartitionEntry     uint32              `json:"sizeofpartitionentry,omitempty" cbor:"12,keyasint,omitempty"`
	PartitionEntryArrayCRC32 uint32              `json:"partitionentryarraycrc32,omitempty" cbor:"13,keyasint,omitempty"`
	Partitions               []GPTPartitionEntry `json:"partitions,omitempty" cbor:"13,keyasint,omitempty"`
}

type GPTPartitionEntry struct {
	PartitionTypeGUID   string `json:"paritiontypeguid,omitempty" cbor:"0,keyasint,omitempty"`
	UniquePartitionGUID string `json:"uniquepartitionguid,omitempty" cbor:"0,keyasint,omitempty"`
	StartingLBA         uint64 `json:"startinglba,omitempty" cbor:"0,keyasint,omitempty"`
	EndingLBA           uint64 `json:"endinglba,omitempty" cbor:"0,keyasint,omitempty"`
	Attributes          uint64 `json:"attributes,omitempty" cbor:"0,keyasint,omitempty"`
	ParitionName        string `json:"partitionname,omitempty" cbor:"0,keyasint,omitempty"` //ParitionName parsed in [36] UTF16
}

type PCClientTaggedEvent struct {
	TaggedEventID uint32 `json:"taggedeventid" cbor:"0,keyasint"`
	// TaggedEventDataSize uint32
	TaggedEventData HexByte `json:"taggedeventdata" cbor:"0,keyasint"`
}

type ImageLoadEvent struct {
	ImageLocationInMemory address `json:"imagelocationinmemory" cbor:"0,keyasint"` //(assume 64 bit architecture)
	ImageLengthInMemory   uint64  `json:"imagelengthinmemory" cbor:"1,keyasint"`
	ImageLinkTimeAddress  uint64  `json:"imagelinktimeaddress" cbor:"2,keyasint"`
	// LengthOfDevicePath uint64
	//device path
	UefiDevicePath *FilePathList `json:"uefidevicepath" cbor:"3,keyasint"`
}

type UefiHandoffTablePointer struct {
	// NumberOfTables uint64
	TableEntry []UefiConfigurationTable `json:"ueficonfigurationtable" cbor:"0,keyasint"`
}

type UefiConfigurationTable struct {
	EFIGuid     string  `json:"guid" cbor:"0,keyasint"`
	VendorTable address `json:"tableaddress" cbor:"1,keyasint"`
}

type UefiPlatformFirmwareBlob struct {
	BlobBase   HexByte `json:"blobbase" cbor:"0,keyasint"` //(assumes 64 bit architecture)
	BlobLength HexByte `json:"bloblength" cbor:"1,keyasint"`
}

//main method for parsing the eventData --------------------------------------

func ParseEventData(eventBytes []uint8, eventName string, addRawEventData bool) *EventData {
	exInfo := new(EventData)
	switch eventName {
	case "EV_EFI_VARIABLE_DRIVER_CONFIG", "EV_EFI_VARIABLE_BOOT", "EV_EFI_VARIABLE_AUTHORITY":
		exInfo.Uefivariabledata = parseUefiVariableData(bytes.NewBuffer(eventBytes))
	case "EV_EFI_GPT_EVENT":
		exInfo.GPTHeader = parseUefiGPTEvent(bytes.NewBuffer(eventBytes))
	case "EV_EFI_BOOT_SERVICES_APPLICATION", "EV_EFI_BOOT_SERVICES_DRIVER", "EV_EFI_RUNTIME_SERVICES_DRIVER":
		exInfo.ImageLoadEvent = parseImageLoadEvent(bytes.NewBuffer(eventBytes))
	case "EV_EVENT_TAG":
		exInfo.PCClientTaggedEvent = parsePCClientTaggedEvent(bytes.NewBuffer(eventBytes))
	case "EV_EFI_PLATFORM_FIRMWARE_BLOB":
		exInfo.UefiPlatformFirmwareBlob = parseUefiPlatformFirmwareBlob(bytes.NewBuffer(eventBytes))
	case "EV_EFI_HANDOFF_TABLES":
		exInfo.UefiHandoffTablePointer = parseEFIHandoffTables(bytes.NewBuffer(eventBytes))
	case "EV_IPL", "EV_EFI_ACTION", "EV_POST_CODE", "EV_S_CRTM_VERSION", "EV_OMIT_BOOT_DEVICE_EVENTS":
		exInfo.StringContent = bytesToString(eventBytes)
	}

	if addRawEventData {
		exInfo.RawData = eventBytes
	}

	if EmptyEventdata(exInfo) {
		return nil
	}

	return exInfo

}

//methods for parsing the structures from eventlog data --------------------------------------

func EmptyEventdata(evData *EventData) bool {
	return evData.Uefivariabledata == nil &&
		evData.GPTHeader == nil &&
		evData.PCClientTaggedEvent == nil &&
		evData.ImageLoadEvent == nil &&
		evData.UefiHandoffTablePointer == nil &&
		evData.UefiPlatformFirmwareBlob == nil &&
		len(evData.StringContent) == 0 &&
		evData.RawData == nil
}

// read the GUID from a buffer
func readGUID(buf *bytes.Buffer) string {
	var val1 uint32
	var val2 uint16
	var val3 uint16
	var val4 [2]byte
	var val5 [6]byte

	//reading the values
	binary.Read(buf, binary.LittleEndian, &val1)
	binary.Read(buf, binary.LittleEndian, &val2)
	binary.Read(buf, binary.LittleEndian, &val3)
	binary.Read(buf, binary.LittleEndian, &val4)
	binary.Read(buf, binary.LittleEndian, &val5)

	output := fmt.Sprintf("%08x", val1)
	output += "-"
	output += fmt.Sprintf("%04x", val2)
	output += "-"
	output += fmt.Sprintf("%04x", val3)
	output += "-"
	output += hex.EncodeToString(val4[:])
	output += "-"
	output += hex.EncodeToString(val5[:])

	return output
}

func readUTF16UntilNull(buffer *bytes.Buffer) (string, error) {
	utf16buf := make([]uint16, 0)

	for {
		// Read two bytes from the buffer
		b1, err := buffer.ReadByte()
		if err != nil {
			return "", err
		}

		b2, err := buffer.ReadByte()
		if err != nil {
			return "", err
		}

		// Check for null-terminated byte
		if b1 == 0 && b2 == 0 {
			break
		}

		// Convert bytes to UTF-16 character
		utf16char := []uint16{uint16(b1) | (uint16(b2) << 8)}

		utf16buf = append(utf16buf, utf16char[0])

	}

	// Convert UTF-16 buffer to string
	utf16String := string(utf16.Decode(utf16buf[:]))

	return utf16String, nil
}

// simple convert function, that interprets bytes as string (does not dispose)
func bytesToString(uint8Array []uint8) string {
	result := ""
	for _, val := range uint8Array {
		if val < 128 && (val > 27 || (val < 14 && val > 8)) {
			result += string(val)
		} else {
			result += "."
		}
	}
	return result
}

func parseUefiVariableData(buf *bytes.Buffer) *UefiVariableData {

	if buf.Len() >= 32 {
		uefiVariableData := new(UefiVariableData)
		var unicodeNameLength, variableDataLength uint64

		//1. Part: read binary data into variables
		variableName := readGUID(buf)
		binary.Read(buf, binary.LittleEndian, &unicodeNameLength)
		binary.Read(buf, binary.LittleEndian, &variableDataLength)

		//read the amount of data into the []data fields

		if buf.Len() < 2*int(unicodeNameLength) {
			// return output
			log.Error("incomplete UEFI Variable Data field")
			return uefiVariableData
		}

		unicodeNameBuf := make([]uint16, unicodeNameLength)
		binary.Read(buf, binary.LittleEndian, &unicodeNameBuf)
		unicodeName := string(utf16.Decode(unicodeNameBuf))

		if buf.Len() < int(variableDataLength) {
			//just stop reading
			log.Error("incomplete UEFI Variable Data field")
			return uefiVariableData
		}

		//2. Part: put data into struct
		uefiVariableData.VariableNameGUID = variableName
		uefiVariableData.UnicodeName = unicodeName

		//parse data of UEFI var
		switch unicodeName {
		case "PK", "KEK", "db", "dbr", "dbt", "dbx", "PKDefault", "KEKDefault", "dbDefault", "dbrDefault", "dbtDefault", "dbxDefault":
			uefiVariableData.Signaturedb = parseEFISignaturedb(buf, int(variableDataLength))
		case "BootOrder":
			uefiVariableData.BootOrder = parseEFIBootOrder(buf, int(variableDataLength))
		case "DriverOrder":
			uefiVariableData.DriverOrder = parseEFIBootOrder(buf, int(variableDataLength))
		case "BootNext":
			uefiVariableData.BootNext = *parseSingleUint16(buf)
		case "BootCurrent":
			uefiVariableData.BootCurrent = *parseSingleUint16(buf)
		case "BootOptionSupport":
			uefiVariableData.BootOptionSupport = *parseSingleUint32(buf)
		case "SignatureSupport", "OsRecoveryOrder":
			//parse an array of GUIDs
			guidArray := make([]string, int(variableDataLength)/16)
			for i := 0; i < int(variableDataLength)/16; i++ {
				guidArray[i] = readGUID(buf)
			}
			uefiVariableData.GUIDArray = guidArray
		case "PlatformLangCodes", "PlatformLang":
			//read null terminated asciiString
			if buf.Len() >= int(variableDataLength) {
				uefiVariableData.StringContent = string(buf.Next(int(variableDataLength)))
			}
		default:
			//if string is of type BootXXXX
			if (strings.Contains(unicodeName, "Boot")) || strings.Contains(unicodeName, "PlatformRecovery") || strings.Contains(unicodeName, "Driver") { //for BootXXXX, PlatformRecoveryXXXX, and DriverXXXX entries
				uefiVariableData.EFILoadOption = parseEFILoadOption(buf)
			} else {
				hexString := (buf.Next(int(variableDataLength)))
				uefiVariableData.VariableData = hexString
			}
		}

	}

	return nil
}

func parseEFILoadOption(buf *bytes.Buffer) *EFILoadOption {
	efiloadoption := new(EFILoadOption)
	var filePathListLength uint16

	binary.Read(buf, binary.LittleEndian, &efiloadoption.Attributes)
	binary.Read(buf, binary.LittleEndian, &filePathListLength)
	descr, err := readUTF16UntilNull(buf)
	if err != nil {
		return nil
	}
	efiloadoption.Description = descr

	//start parsing the file path list
	//loop that checks if the buffer still contains a minimum number of possible filepaths
	efiloadoption.FilepathList = make([]FilePathList, 0) //if they are empty, dispose

	// buffer needs to stop at sizeof(UINT32) + sizeof(UINT16) + StrSize(Description) + FilePathListLength of the EFI_LOAD_OPTION
	bufferLengthPreParsing := buf.Len()
	parsedBytes := 0
	for parsedBytes < int(filePathListLength) {
		fpl := parseFilePathList(buf)
		if fpl != nil {
			efiloadoption.FilepathList = append(efiloadoption.FilepathList, *fpl)
			break
		}

		//sets the buffer length to correct parsing structure
		parsedBytes = bufferLengthPreParsing - buf.Len()
	}
	if buf.Len() > 0 {
		//contains optional data

		efiloadoption.OptionalData = (buf.Next(buf.Len()))
	}

	return efiloadoption
}

func parseFilePathList(buf *bytes.Buffer) *FilePathList {
	filepathlist := new(FilePathList)
	var fplType, fplSubtype byte
	var length uint16

	binary.Read(buf, binary.LittleEndian, &fplType)
	binary.Read(buf, binary.LittleEndian, &fplSubtype)
	binary.Read(buf, binary.LittleEndian, &length)

	//end of entries marked with filetype:= 127 (0x7f); subtype:=255 (0xff); length := 4
	if fplType == 127 && fplSubtype == 255 {
		buf.Next(1)
		//return nothing
		return nil
	}

	//example!, the UEFI specification contains more file types
	switch fplType {
	case 2:
		filepathlist.Type = "ACPI Device Path"
		switch fplSubtype {
		case 1:
			if length == 12 { //Always 12 Bytes long
				filepathlist.Subtype = "ACPI Device Path"
				filepathlist.HID = buf.Next(4)
				filepathlist.UID = buf.Next(4)
			}
		}

	case 3:
		filepathlist.Type = "messaging device path"
		switch fplSubtype {
		case 0xa:
			filepathlist.Subtype = "vendor-defined messaging device path"
			//parsing the GUID
			filepathlist.VendorGUID = readGUID(buf)
			filepathlist.VendorDefinedData = (buf.Next(int(length) - 20))
		}
	case 4: //(media device path)
		filepathlist.Type = "media device path"
		switch fplSubtype {
		case 1:
			if length == 42 { //always 42 Bytes long
				filepathlist.Subtype = "hard drive"
				//parsing of remaining attributes
				binary.Read(buf, binary.LittleEndian, &filepathlist.PartitionNumber)
				binary.Read(buf, binary.LittleEndian, &filepathlist.PartitionStart)
				binary.Read(buf, binary.LittleEndian, &filepathlist.PartitionSize)
				filepathlist.PartitionSignature = buf.Next(16)
				binary.Read(buf, binary.LittleEndian, &filepathlist.PartitionFormat)
				binary.Read(buf, binary.LittleEndian, &filepathlist.SignaturType)

			} else {
				log.Error("incompatible length of file path argument")
			}
		case 2:
			if length == 24 { //always 24 Bytes long
				filepathlist.Subtype = "CD-ROM “El Torito” Format"
				binary.Read(buf, binary.LittleEndian, &filepathlist.BootEntry)
				binary.Read(buf, binary.LittleEndian, &filepathlist.PartitionStart)
				binary.Read(buf, binary.LittleEndian, &filepathlist.PartitionSize)
			} else {
				log.Error("incompatible length of file path argument")
			}
		case 3:
			if length >= 20 { //20 + n Bytes long
				filepathlist.Subtype = "Vendor"
				//readVendor guid
				filepathlist.VendorGUID = readGUID(buf)
				filepathlist.VendorDefinedData = (buf.Next(int(length) - 20))
			} else {
				log.Error("incompatible length of file path argument")
			}

		case 4:
			filepathlist.Subtype = "file path media device path"
			bufferLengthPreParsing := buf.Len()
			parsedBytes := 0
			for parsedBytes < int(length)-4 {
				str, _ := readUTF16UntilNull(buf)
				filepathlist.PathName += str
				parsedBytes = bufferLengthPreParsing - buf.Len()
			}
		case 5:
			if length == 20 { //20 Bytes long
				filepathlist.Subtype = "Media Protocol"
				filepathlist.ProtocolGUID = readGUID(buf)
			} else {
				log.Error("incompatible length of file path argument")
			}
		case 7:
			if length >= 4 { //4 + n Bytes long
				filepathlist.Subtype = "PIWG Firmware Volume"
				filepathlist.VendorDefinedData = (buf.Next(int(length) - 4))
			} else {
				log.Error("incompatible length of file path argument")
			}
		case 9:
			if length == 38 { //20 Bytes long
				filepathlist.Subtype = "RAM Disk Device Path"
				binary.Read(buf, binary.LittleEndian, &filepathlist.StartingAddress)
				binary.Read(buf, binary.LittleEndian, &filepathlist.EndingAddress)
				filepathlist.DiskTypeGUID = readGUID(buf)
				binary.Read(buf, binary.LittleEndian, &filepathlist.DiskInstance)
			} else {
				log.Error("incompatible length of file path argument")
			}
		}
	case 5:
		filepathlist.Type = "BIOS Boot Specification Device Path."
		if fplSubtype == 1 {
			if length >= 8 { //8 + n Bytes long
				filepathlist.Subtype = "BIOS Boot Specification Version 1.01"
				binary.Read(buf, binary.LittleEndian, &filepathlist.DeviceType)
				binary.Read(buf, binary.LittleEndian, &filepathlist.StatusFlag)

				asciiString := make([]byte, length-8)
				binary.Read(buf, binary.LittleEndian, &asciiString)
				filepathlist.DescriptionString = string(asciiString)

			} else {
				log.Error("incompatible length of file path argument")
			}
		}
	default:
		log.Tracef("Type: %v, Subtype %v", fplType, fplSubtype)

	}
	return filepathlist
}

func parseSingleUint16(buf *bytes.Buffer) *uint16 {
	if buf.Len() >= 2 {
		var out uint16
		binary.Read(buf, binary.LittleEndian, &out)
		return &out
	}
	log.Error("incomplete Datafield")
	return nil
}

func parseSingleUint32(buf *bytes.Buffer) *uint32 {
	if buf.Len() >= 2 {
		var out uint32
		binary.Read(buf, binary.LittleEndian, &out)
		return &out
	}
	log.Error("incomplete Datafield")
	return nil
}

func parseEFIBootOrder(buf *bytes.Buffer, size int) []uint16 {
	if buf.Len() >= size {
		order := make([]uint16, size/2)
		binary.Read(buf, binary.LittleEndian, &order)
		return order
	}
	log.Error("incomplete Datafield")
	return nil
}

func parseEFISignaturedb(buf *bytes.Buffer, signatureDBSize int) []SignatureDatabase {
	//calculate size of signature Database, and the number of signature dbs
	//signatureDBSize = bytes used in the whole []signaturelist

	//signature of a single signature in one signature list
	readBytes := 0

	signatureDatabase := make([]SignatureDatabase, 0)

	for buf.Len() >= 28 && readBytes < signatureDBSize { //maybe some size checks
		sigdb := SignatureDatabase{}

		//read the first signatureDatabase
		sigdb.SignatureTypeGUID = readGUID(buf)

		var signatureListSize, signatureHeaderSize, signatureSize uint32
		binary.Read(buf, binary.LittleEndian, &signatureListSize)
		binary.Read(buf, binary.LittleEndian, &signatureHeaderSize)
		binary.Read(buf, binary.LittleEndian, &signatureSize)

		//parsing the Signature Header
		sigdb.SignatureHeader = buf.Next(int(signatureHeaderSize))

		//parsing the signatures
		//countes how often a certificate has been parsed
		counter := 0
		//2nd condition determines if SignatureDB contains multiple Certificates
		certsize := int(signatureSize) - 16
		certs := make([]UEFICertificate, 0) //if they are empty, dispose
		hashes := make([]Hash, 0)           //if they are empty, dispose

		for buf.Len() >= int(signatureSize) && int(signatureListSize)-counter*int(signatureSize) >= int(signatureSize) {
			sigOwner := readGUID(buf)

			switch sigdb.SignatureTypeGUID {
			case "a5c059a1-94e4-4aa7-87b5-ab155c2bf072": //EFI_CERT_X509_GUID
				cert := UEFICertificate{}
				cert.SignatureOwnerGUID = sigOwner
				cert.Certificates = parseVariableDataX509_GUID(buf, certsize)
				certs = append(certs, cert)
			case "826ca512-cf10-4ac9-b187-be01496631bd": //EFI_CERT_SHA1_GUID
				hash := Hash{}
				hash.SignatureOwnerGUID = sigOwner
				hash.Hash = parseVariableDataHash_GUID(buf, SHA1_DIGEST_LEN)
				hashes = append(hashes, hash)
			case "c1c41626-504c-4092-aca9-41f936934328": //EFI_CERT_SHA256_GUID
				hash := Hash{}
				hash.SignatureOwnerGUID = sigOwner
				hash.Hash = parseVariableDataHash_GUID(buf, SHA256_DIGEST_LEN)
				hashes = append(hashes, hash)
			case "ff3e5307-9fd0-48c9-85f1-8ad56c701e01": //EFI_CERT_SHA384_GUID
				hash := Hash{}
				hash.SignatureOwnerGUID = sigOwner
				hash.Hash = parseVariableDataHash_GUID(buf, SHA384_DIGEST_LEN)
				hashes = append(hashes, hash)
			default:
				log.Debugf("Signature GUID %v", sigdb.SignatureTypeGUID)
			}
			//incomplete, to support more types: (Unified Extensible Firmware Interface Specification 2.10 p.1427)
			counter++
		}
		if len(certs) > 0 {
			sigdb.Certificates = certs
		}
		if len(hashes) > 0 {
			sigdb.Sha256Hash = hashes
		}

		//add the element ot the list
		signatureDatabase = append(signatureDatabase, sigdb)
	}

	return signatureDatabase
}
func parseVariableDataX509_GUID(buf *bytes.Buffer, certsize int) X509CertExtracted {
	certBuf := make([]uint8, certsize)
	binary.Read(buf, binary.LittleEndian, &certBuf)

	cert, err := x509.ParseCertificate(certBuf)
	if err != nil {
		log.Error("Failed to parse certificate:")
	}

	//extract the cert
	return ExtractX509Infos(cert)
}

// hashlen in bytes e.g. (32 = sha256)
func parseVariableDataHash_GUID(buf *bytes.Buffer, hashlen int) HexByte {
	return (buf.Next(hashlen))
}

// for UEFI_GPT_EVENT
func parseUefiGPTEvent(buf *bytes.Buffer) *GPTHeader {

	//minimum length UEFI_PARTITION_TABLE_HEADER = 92 bytes
	if buf.Len() >= 92 {
		partitionTableHeader := new(GPTHeader)
		//readall GPTHeader Data
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.Signature)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.Revision)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.HeaderSize)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.HeaderCRC32)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.Reserved)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.MyLBA)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.AlternativeLBA)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.FirstUsableLBA)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.LastUsableLBA)
		//DiskGUID
		partitionTableHeader.DiskGUID = readGUID(buf)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.PartitionEntryLBA)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.NumberOfPartitionEntries)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.SizeOfPartitionEntry)
		binary.Read(buf, binary.LittleEndian, &partitionTableHeader.PartitionEntryArrayCRC32)

		//reading the number of Partitions
		var numberOfPartitions uint64
		binary.Read(buf, binary.LittleEndian, &numberOfPartitions)

		gptPartitions := make([]GPTPartitionEntry, 0)

		//reading the partitions
		if buf.Len() >= int(numberOfPartitions)*128 { //128 Bytes: min size of a GPT Partition Entry
			{
				for i := 0; i < int(numberOfPartitions); i++ {
					partition := GPTPartitionEntry{}
					//Partition Type GUID
					partition.PartitionTypeGUID = readGUID(buf)

					//Unique Partition GUID
					partition.UniquePartitionGUID = readGUID(buf)
					binary.Read(buf, binary.LittleEndian, &partition.StartingLBA)
					binary.Read(buf, binary.LittleEndian, &partition.EndingLBA)
					binary.Read(buf, binary.LittleEndian, &partition.Attributes)

					var paritionName [36]uint16
					binary.Read(buf, binary.LittleEndian, &paritionName)

					partition.ParitionName = string(utf16.Decode(paritionName[:]))

					//appending the partition
					gptPartitions = append(gptPartitions, partition)
				}
			}
		}
		partitionTableHeader.Partitions = gptPartitions

		return partitionTableHeader
	}

	return nil
}

func parsePCClientTaggedEvent(buf *bytes.Buffer) *PCClientTaggedEvent {
	//minimum length parsePCClientTaggedEvent 4 B + 4 B
	if buf.Len() >= 8 {
		taggedEvent := new(PCClientTaggedEvent)
		var taggedEventDataSize uint32
		binary.Read(buf, binary.LittleEndian, &taggedEvent.TaggedEventID)
		binary.Read(buf, binary.LittleEndian, &taggedEventDataSize)

		//reading of TaggedEventData
		if buf.Len() >= int(taggedEventDataSize) {
			taggedEvent.TaggedEventData = (buf.Next(int(taggedEventDataSize)))
		} else {
			log.Error("incomplete PCClientTaggedEvent data")
		}
		return taggedEvent
	}
	log.Error("incomplete PCClientTaggedEvent data")
	return nil
}

func parseImageLoadEvent(buf *bytes.Buffer) *ImageLoadEvent {
	if buf.Len() >= 20 {
		imagelevent := new(ImageLoadEvent)
		binary.Read(buf, binary.LittleEndian, &imagelevent.ImageLocationInMemory)
		binary.Read(buf, binary.LittleEndian, &imagelevent.ImageLengthInMemory)
		binary.Read(buf, binary.LittleEndian, &imagelevent.ImageLinkTimeAddress)
		var lengthOfDevicePath uint64
		binary.Read(buf, binary.LittleEndian, &lengthOfDevicePath)
		imagelevent.UefiDevicePath = parseFilePathList(buf)
		return imagelevent
	}
	return nil
}

func parseEFIHandoffTables(buf *bytes.Buffer) *UefiHandoffTablePointer {
	if buf.Len() >= 8 {
		uefiHandoffTablePointer := new(UefiHandoffTablePointer)
		var numberOfTables uint64
		binary.Read(buf, binary.LittleEndian, &numberOfTables)

		//check possible length: len(GUID) = 16 + len(address) = 8  => 24 Bytes per table
		if buf.Len() >= 24*int(numberOfTables) {
			uefiConfigurationTable := make([]UefiConfigurationTable, 0)
			for i := 0; i < int(numberOfTables); i++ {
				//read GUID
				var conTable UefiConfigurationTable
				conTable.EFIGuid = readGUID(buf)

				//read address
				binary.Read(buf, binary.LittleEndian, &conTable.VendorTable)

				//append to table
				uefiConfigurationTable = append(uefiConfigurationTable, conTable)
			}
			uefiHandoffTablePointer.TableEntry = uefiConfigurationTable
		} else {
			return nil
		}
		return uefiHandoffTablePointer
	}
	return nil
}
func reverse(bytes HexByte) HexByte {
	for i := 0; i < len(bytes)/2; i++ {
		j := len(bytes) - i - 1
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}

func parseUefiPlatformFirmwareBlob(buf *bytes.Buffer) *UefiPlatformFirmwareBlob {
	if buf.Len() >= 16 {
		uefiPlatformFirmwareBlob := new(UefiPlatformFirmwareBlob)
		// binary.Read(buf, binary.LittleEndian, &uefiPlatformFirmwareBlob.BlobBase)
		uefiPlatformFirmwareBlob.BlobBase = reverse(buf.Next(8))
		// binary.Write(, binary.LittleEndian, myInt)
		uefiPlatformFirmwareBlob.BlobLength = reverse(buf.Next(8))
		// binary.Read(buf, binary.LittleEndian, &uefiPlatformFirmwareBlob.BlobLength)
		return uefiPlatformFirmwareBlob
	}
	return nil
}

//-------------------------------------
