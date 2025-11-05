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
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/urfave/cli/v3"
)

var precomputeSnpMrCommand = &cli.Command{
	Name:  "snp",
	Usage: "precompute the values of the AMD SEV-SNP measurement register based on the OVMF and other optional files",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  kernelFlag,
			Usage: "Optional filename of the kernel image",
		},
		&cli.StringFlag{
			Name:  initRfsFlag,
			Usage: "Optional filename of the initramfs",
		},
		&cli.StringFlag{
			Name:  cmdFlag,
			Usage: "Optional filename of the kernel commandline",
		},
		&cli.StringFlag{
			Name:  ovmfFlag,
			Usage: "Optional filename of the OVMF.fd file",
		},
		&cli.UintFlag{
			Name:  vcpuCountFlag,
			Usage: "Set number of vCPUs to use",
			Value: 1,
		},
		&cli.StringFlag{
			Name:  vmmTypeFlag,
			Usage: fmt.Sprintf("VMM type to use [%s, %s]", VmmTypeQemu.Label, VmmTypeEc2.Label),
			Value: VmmTypeQemu.Label,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := PrecomputeSnp(cmd)
		if err != nil {
			return fmt.Errorf("failed to precompute snp: %w", err)
		}
		return nil
	},
}

type SnpHash = [sha512.Size384]byte

const (
	kernelFlag    = "kernel"
	initRfsFlag   = "initrd"
	cmdFlag       = "cmdline"
	ovmfFlag      = "ovmf"
	vcpuCountFlag = "vcpus"
	vmmTypeFlag   = "vmm-type"
)

type VmmType = int

type VmmStruct struct {
	Value VmmType
	Label string
}

var (
	VmmTypeQemu = VmmStruct{Value: VmmType(1), Label: "qemu"}
	VmmTypeEc2  = VmmStruct{Value: VmmType(2), Label: "ec2"}
)

type PageType = uint8

const (
	snpPageTypeReserved   = PageType(0x00)
	snpPageTypeNormal     = PageType(0x01)
	snpPageTypeVmsa       = PageType(0x02)
	snpPageTypeZero       = PageType(0x03)
	snpPageTypeUnmeasured = PageType(0x04)
	snpPageTypeSecrets    = PageType(0x05)
	snpPageTypeCpuid      = PageType(0x06)
)

var snpPageTypeStrings = map[PageType]string{
	snpPageTypeReserved:   "SNP_PAGE_TYPE_RESERVED",
	snpPageTypeNormal:     "SNP_PAGE_TYPE_NORMAL",
	snpPageTypeVmsa:       "SNP_PAGE_TYPE_VMSA",
	snpPageTypeZero:       "SNP_PAGE_TYPE_ZERO",
	snpPageTypeUnmeasured: "SNP_PAGE_TYPE_UNMEASURED",
	snpPageTypeSecrets:    "SNP_PAGE_TYPE_SECRETS",
	snpPageTypeCpuid:      "SNP_PAGE_TYPE_CPUID",
}

type PrecomputedSnpConf struct {
	Kernel    string
	InitRfs   string
	CmdLine   string
	OvmfFile  string
	vcpuCount int
	vmmType   VmmType
}
type snpSevHashTableEntry struct {
	Guid   [16]byte
	Length uint16
	hash   [sha256.Size]byte
}
type snpSevHashTable struct {
	Guid    [16]byte
	Length  uint16
	Cmdline snpSevHashTableEntry
	InitRfs snpSevHashTableEntry
	Kernel  snpSevHashTableEntry
}
type snpLaunchUpdatePageInfo struct {
	Digest   [sha512.Size384]byte
	Contents [sha512.Size384]byte
	Length   uint16
	PageType uint8

	// only bit[0] used, bits[1:7] are reserved
	ImiPage    uint8
	_reserved  uint8
	Vmpl1Perms uint8
	Vmpl2Perms uint8
	Vmpl3Perms uint8
	Gpa        uint64
}

type snpVmcbSegment struct {
	Selector  uint16
	Attribute uint16
	Limit     uint32
	Base      uint64
}

type snpVmcbSaveArea struct {
	Es, Cs, Ss, Ds, Fs, Gs                               snpVmcbSegment
	Gdtr, Ldtr, Idtr, Tr                                 snpVmcbSegment
	Vmpl0Ssp, Vmpl1Ssp, Vmpl2Ssp, Vmpl3Ssp               uint64
	UCet                                                 uint64
	Reserved0xc8                                         [2]uint8
	Vmpl, Cpl                                            uint8
	Reserved0xcc                                         [4]uint8
	Efer                                                 uint64
	Reserved0xd8                                         [104]uint8
	Xss                                                  uint64
	Cr4, Cr3, Cr0                                        uint64
	Dr7, Dr6                                             uint64
	Rflags, Rip                                          uint64
	Dr0, Dr1, Dr2, Dr3                                   uint64
	Dr0AddrMask, Dr1AddrMask, Dr2AddrMask, Dr3AddrMask   uint64
	Reserved0x1c0                                        [24]uint8
	Rsp, SCet, Ssp, IsstAddr                             uint64
	Rax, Star, Lstar, Cstar, Sfmask                      uint64
	KernelGsBase, SysenterCs, SysenterEsp, SysenterEip   uint64
	Cr2                                                  uint64
	Reserved0x248                                        [32]uint8
	GPat, Dbgctl, BrFrom, BrTo, LastExcpFrom, LastExcpTo uint64
	Reserved0x298                                        [80]uint8
	Pkru, TscAux                                         uint32
	Reserved0x2f0                                        [24]uint8
	Rcx, Rdx, Rbx                                        uint64
	// rsp already available at 0x01d8
	Reserved0x320                                               uint64
	Rbp, Rsi, Rdi                                               uint64
	R8, R9, R10, R11, R12, R13, R14, R15                        uint64
	Reserved0x380                                               [16]uint8
	GuestExitInfo1, GuestExitInfo2, GuestExitIntInfo, GuestNrip uint64
	SevFeatures, VintrCtrl, GuestExitCode, VirtualTom           uint64
	TlbId, PcpuId, EventInj, Xcr0                               uint64
	Reserved0x3f0                                               [16]uint8
	X87Dp                                                       uint64
	Mxcsr                                                       uint32
	X87Ftw, X87Fsw, X87Fcw, X87Fop                              uint16
	X87Ds, X87Cs                                                uint16
	X87Rip                                                      uint64
	FpregX87                                                    [80]uint8
	FpregXmm                                                    [256]uint8
	FpregYmm                                                    [256]uint8
}

func getSnpConf(cmd *cli.Command) (*PrecomputedSnpConf, error) {
	// parse the config (default to empty string)
	config := &PrecomputedSnpConf{}
	if cmd.IsSet(kernelFlag) {
		config.Kernel = cmd.String(kernelFlag)
	}
	if cmd.IsSet(initRfsFlag) {
		config.InitRfs = cmd.String(initRfsFlag)
	}
	if cmd.IsSet(cmdFlag) {
		config.CmdLine = cmd.String(cmdFlag)
	}
	if cmd.IsSet(ovmfFlag) {
		config.OvmfFile = cmd.String(ovmfFlag)
	}

	// [vcpuCountFlag] must be available, as its defaulted
	config.vcpuCount = int(cmd.Uint(vcpuCountFlag))

	// validate the config
	if len(config.OvmfFile) == 0 {
		return nil, fmt.Errorf("OVMF must be specified and must not be an empty string. See mrtool precompute snp --help")
	}
	if config.vcpuCount <= 0 {
		return nil, fmt.Errorf("number of vcpus must be greater than zero. See mrtool precompute snp --help")
	}

	// match the vmm-type ([vmmTypeFlag] must be set, as its defaulted)
	switch cmd.String(vmmTypeFlag) {
	case VmmTypeQemu.Label:
		config.vmmType = VmmTypeQemu.Value
	case VmmTypeEc2.Label:
		config.vmmType = VmmTypeEc2.Value
	default:
		return nil, fmt.Errorf("unsupported vmm-type [%s] encountered. See mrtool precompute snp --help", cmd.String(vmmTypeFlag))
	}

	// log the config for debugging purposes
	log.Debugf("SNP Config")
	if len(config.Kernel) > 0 {
		log.Debugf("\tKernel file       : %q", config.Kernel)
	}
	if len(config.InitRfs) > 0 {
		log.Debugf("\tInit ramfs file   : %q", config.InitRfs)
	}
	if len(config.CmdLine) > 0 {
		log.Debugf("\tKernel commandline: %q", config.CmdLine)
	}
	log.Debugf("\tOVMF file         : %q", config.OvmfFile)
	return config, nil
}

func PrecomputeSnp(cmd *cli.Command) error {
	globConf, err := getGlobalConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	snpConfig, err := getSnpConf(cmd)
	if err != nil {
		return fmt.Errorf("invalid snp config: %w", err)
	}

	hash, err := performSnpPrecomputation(snpConfig)
	if err != nil {
		return err
	}

	// setup the reference value for the event log (as slice with single value)
	refValue := [1]attestationreport.ReferenceValue{
		attestationreport.ReferenceValue{
			Type:        "SNP Reference Value",
			SubType:     "SNP Launch Digest",
			Index:       0,
			Sha384:      hash[:],
			Description: fmt.Sprintf("SNP launch digest for %d vCPUs", snpConfig.vcpuCount),
		},
	}

	// marshal eventlog
	data, err := json.MarshalIndent(refValue, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal reference values: %w", err)
	}

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		os.Stdout.Write(append(data, []byte("\n")...))
	}
	return nil
}

func performSnpSetupHashTablePage(cmdline, kernel, initRfs string) ([]byte, error) {
	var err error

	// read the command line to a buffer and append the trailing zero-byte and compute its hash
	cmdlineData := []byte{}
	if len(cmdline) > 0 {
		cmdlineData, err = os.ReadFile(cmdline)
		if err != nil {
			return nil, fmt.Errorf("failed to read commandline: %w", err)
		}
		cmdlineData = append(cmdlineData, 0)
		log.Debugf("Commandline data size: %d", len(cmdlineData))
	}
	cmdlineHash := sha256.Sum256(cmdlineData)

	// read the kernel to a buffer and compute its hash (must exist)
	kernelData, err := os.ReadFile(kernel)
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel: %w", err)
	}
	log.Debugf("Kernel data size: %d", len(kernelData))
	kernelHash := sha256.Sum256(kernelData)

	// read the initial ram fs to a buffer and compute its hash
	initRfsData := []byte{}
	if len(initRfs) > 0 {
		initRfsData, err = os.ReadFile(initRfs)
		if err != nil {
			return nil, fmt.Errorf("failed to read initrfs: %w", err)
		}
		log.Debugf("Initrfs data size: %d", len(initRfsData))
	}
	initRfsHash := sha256.Sum256(initRfsData)

	// populate the output structure
	table := snpSevHashTable{
		Guid: [16]byte{0x06, 0xd6, 0x38, 0x94, 0x22, 0x4f, 0xc9, 0x4c, 0xb4, 0x79, 0xa7, 0x93, 0xd4, 0x11, 0xfd, 0x21},
		Cmdline: snpSevHashTableEntry{
			Guid: [16]byte{0xd8, 0x2d, 0xd0, 0x97, 0x20, 0xbd, 0x94, 0x4c, 0xaa, 0x78, 0xe7, 0x71, 0x4d, 0x36, 0xab, 0x2a},
			hash: cmdlineHash,
		},
		InitRfs: snpSevHashTableEntry{
			Guid: [16]byte{0x31, 0xf7, 0xba, 0x44, 0x2f, 0x3a, 0xd7, 0x4b, 0x9a, 0xf1, 0x41, 0xe2, 0x91, 0x69, 0x78, 0x1d},
			hash: initRfsHash,
		},
		Kernel: snpSevHashTableEntry{
			Guid: [16]byte{0x37, 0x94, 0xe7, 0x4d, 0xd2, 0xab, 0x7f, 0x42, 0xb8, 0x35, 0xd5, 0xb1, 0x72, 0xd2, 0x04, 0x5b},
			hash: kernelHash,
		},
	}

	// patch the dimensions
	table.Length = uint16(binary.Size(table))
	table.Cmdline.Length = uint16(binary.Size(table.Cmdline))
	table.InitRfs.Length = uint16(binary.Size(table.InitRfs))
	table.Kernel.Length = uint16(binary.Size(table.Kernel))

	// log debug information
	log.Debugf("Commandline : %x", cmdlineData)
	log.Debugf("Kernel hash : %x", table.Kernel.hash)
	log.Debugf("Cmdline hash: %x", table.Cmdline.hash)
	log.Debugf("Initrfs hash: %x", table.InitRfs.hash)

	// serialize the data to binary
	buffer := bytes.Buffer{}
	binary.Write(&buffer, binary.LittleEndian, table)
	data := buffer.Bytes()

	// write the data to the page at the corresponding offset
	if len(data) > 1024 {
		return nil, fmt.Errorf("hashtable size is expected to be smaller than 1024 (< %d)", len(data))
	}
	var tempPage [4096]byte
	copy(tempPage[3072:], data)
	return tempPage[:], nil
}

func performSnpUpdatePageInfo(current SnpHash, page []byte, pageType PageType, gpa uint64) SnpHash {
	pageHash := SnpHash{}
	if page != nil {
		pageHash = sha512.Sum384(page)
	}

	// populate the page-info update state
	info := snpLaunchUpdatePageInfo{
		Digest:   current,
		Contents: pageHash,
		PageType: pageType,
		Gpa:      gpa,
	}
	info.Length = uint16(binary.Size(info))

	// log the page-information
	log.Tracef("Page Info:")
	log.Tracef("  digest      : %x", info.Digest)
	log.Tracef("  content     : %x", pageHash)
	log.Tracef("  length      : %#04x", info.Length)
	log.Tracef("  page_type   : %#02x (%s)", info.PageType, snpPageTypeStrings[info.PageType])
	log.Tracef("  imi_page    : %#02x", info.ImiPage)
	log.Tracef("  reserved2   : %#02x", info._reserved)
	log.Tracef("  vmpl_1_perms: %#02x", info.Vmpl1Perms)
	log.Tracef("  vmpl_2_perms: %#02x", info.Vmpl2Perms)
	log.Tracef("  vmpl_3_perms: %#02x", info.Vmpl3Perms)
	log.Tracef("  gpa         : %#016x", info.Gpa)

	// serialize the data to binary and return the accumulating hash
	buffer := bytes.Buffer{}
	binary.Write(&buffer, binary.LittleEndian, info)

	hash := sha512.Sum384(buffer.Bytes())

	log.Tracef("Updated hash: %x", hash)

	return hash
}

func performSnpSetupVmcbSaveAreaPage(eip uint64, vmmType VmmType) ([]byte, error) {
	save := snpVmcbSaveArea{
		// Segment setup
		Es:   snpVmcbSegment{Attribute: 0x93, Limit: 0xffff},
		Cs:   snpVmcbSegment{Selector: 0xf000, Attribute: 0x9b, Limit: 0xffff, Base: (eip & 0xffff0000)},
		Ss:   snpVmcbSegment{Limit: 0xffff},
		Ds:   snpVmcbSegment{Attribute: 0x93, Limit: 0xffff},
		Fs:   snpVmcbSegment{Attribute: 0x93, Limit: 0xffff},
		Gs:   snpVmcbSegment{Attribute: 0x93, Limit: 0xffff},
		Gdtr: snpVmcbSegment{Limit: 0xffff},
		Ldtr: snpVmcbSegment{Attribute: 0x82, Limit: 0xffff},
		Idtr: snpVmcbSegment{Limit: 0xffff},
		Tr:   snpVmcbSegment{Limit: 0xffff},

		// Control registers and flags
		Efer:        0x1000,
		Cr4:         0x40,
		Cr0:         0x10,
		Dr7:         0x400,
		Dr6:         0xffff0ff0,
		Rflags:      0x2,
		Rip:         eip & 0xffff,
		GPat:        0x7040600070406,
		SevFeatures: 0x1,
		Xcr0:        0x1,
	}

	// VMM-specific overrides
	switch vmmType {
	case VmmTypeQemu.Value:
		save.Ss.Attribute = 0x93
		save.Tr.Attribute = 0x8b
		save.Rdx = 0x800f12
		save.Mxcsr = 0x1f80
		save.X87Fcw = 0x37f
	case VmmTypeEc2.Value:
		if eip == 0xfffffff0 {
			save.Cs.Attribute = 0x9a
		}
		save.Ss.Attribute = 0x92
		save.Tr.Attribute = 0x83
		save.Rdx = 0x0
		save.Mxcsr = 0x0
		save.X87Fcw = 0x0
	}

	// serialize the data to binary
	buffer := bytes.Buffer{}
	binary.Write(&buffer, binary.LittleEndian, save)
	data := buffer.Bytes()

	// write the data to the page new page
	if len(data) > 4096 {
		return nil, fmt.Errorf("VMCB save area size is expected to be smaller than 4096 (< %d)", len(data))
	}
	var tempPage [4096]byte
	copy(tempPage[0:], data)
	return tempPage[:], nil
}

func performSnpPrecomputation(config *PrecomputedSnpConf) (SnpHash, error) {
	log.Debug("Precomputing SNP measurement registers...")

	// read the ovmf data
	ovmfData, err := os.ReadFile(config.OvmfFile)
	if err != nil {
		return SnpHash{}, fmt.Errorf("failed to read ofmv file: %w", err)
	}
	if (len(ovmfData) % 4096) != 0 {
		return SnpHash{}, fmt.Errorf("OVMF data are expected to be page aligned: %x", len(ovmfData))
	}
	log.Debugf("OVMF data size: %d", len(ovmfData))

	// add all of the pages
	hashDigest := SnpHash{}
	for i := 0; i < len(ovmfData); i += 4096 {
		hashDigest = performSnpUpdatePageInfo(hashDigest, ovmfData[i:i+4096], snpPageTypeNormal, uint64(0x100000000-len(ovmfData)+i))
	}
	for gpa := uint64(0x00800000); gpa < 0x00809000; gpa += 4096 {
		hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeZero, gpa)
	}
	for gpa := uint64(0x0080a000); gpa < 0x0080d000; gpa += 4096 {
		hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeZero, gpa)
	}
	hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeSecrets, 0x0080d000)
	if config.vmmType == VmmTypeQemu.Value {
		hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeCpuid, 0x0080e000)
	}
	if len(config.Kernel) > 0 {
		hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeZero, 0x80f000)
		hashTablePage, err := performSnpSetupHashTablePage(config.CmdLine, config.Kernel, config.InitRfs)
		if err != nil {
			return SnpHash{}, fmt.Errorf("failed to read commandline file: %w", err)
		}
		hashDigest = performSnpUpdatePageInfo(hashDigest, hashTablePage, snpPageTypeNormal, 0x810000)
		for gpa := uint64(0x00811000); gpa < 0x00820000; gpa += 4096 {
			hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeZero, gpa)
		}
	} else {
		for gpa := uint64(0x0080f000); gpa < 0x00820000; gpa += 4096 {
			hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeZero, gpa)
		}
	}

	if config.vmmType == VmmTypeEc2.Value {
		hashDigest = performSnpUpdatePageInfo(hashDigest, nil, snpPageTypeCpuid, 0x0080e000)
	}

	tempPage, err := performSnpSetupVmcbSaveAreaPage(0xfffffff0, config.vmmType)
	if err != nil {
		return SnpHash{}, fmt.Errorf("failed to setup vmcb save area: %w", err)
	}
	hashDigest = performSnpUpdatePageInfo(hashDigest, tempPage, snpPageTypeVmsa, 0xfffffffff000)

	tempPage, err = performSnpSetupVmcbSaveAreaPage(0x80b004, config.vmmType)
	if err != nil {
		return SnpHash{}, fmt.Errorf("failed to setup vmcb save area: %w", err)
	}
	for i := 1; i < config.vcpuCount; i += 1 {
		hashDigest = performSnpUpdatePageInfo(hashDigest, tempPage, snpPageTypeVmsa, 0xfffffffff000)
	}

	log.Debugf("Calculated Hash: %x", hashDigest)

	// return the accumulative hash
	return hashDigest, nil
}
