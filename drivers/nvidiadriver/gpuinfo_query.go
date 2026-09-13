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

//go:build linux && cgo && (!nodefaults || nvidia)

package nvidiadriver

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>

#define NVML_SUCCESS 0
#define NVML_DEVICE_NAME_BUFFER_SIZE              64
#define NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE     32
#define NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE    80
#define NVML_GPU_CERT_CHAIN_SIZE                  0x1000
#define NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE      0x1400
#define NVML_DEVICE_UUID_V2_BUFFER_SIZE           96
#define NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE   16

typedef struct {
    unsigned int  certChainSize;
    unsigned int  attestationCertChainSize;
    unsigned char certChain[NVML_GPU_CERT_CHAIN_SIZE];
    unsigned char attestationCertChain[NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE];
} nvmlConfComputeGpuCertificate_t;


#define NVML_CC_GPU_CEC_NONCE_SIZE 0x20                //!< Size of the CEC nonce.
#define NVML_CC_GPU_ATTESTATION_REPORT_SIZE 0x2000     //!< Size of the attestation report.
#define NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE 0x1000 //!< Size of the CEC attestation report.
#define NVML_CC_CEC_ATTESTATION_REPORT_NOT_PRESENT 0   //!< CEC attestation report is not present.
#define NVML_CC_CEC_ATTESTATION_REPORT_PRESENT 1       //!< CEC attestation report is present.
#define NVML_CC_KEY_ROTATION_THRESHOLD_ATTACKER_ADVANTAGE_MIN 50 //!< Minimum attacker advantage for key rotation threshold.
#define NVML_CC_KEY_ROTATION_THRESHOLD_ATTACKER_ADVANTAGE_MAX 65 //!< Maximum attacker advantage for key rotation threshold.


typedef struct nvmlConfComputeGpuAttestationReport_st {
    unsigned int isCecAttestationReportPresent;
    unsigned int attestationReportSize;
    unsigned int cecAttestationReportSize;
    unsigned char nonce[NVML_CC_GPU_CEC_NONCE_SIZE];
    unsigned char attestationReport[NVML_CC_GPU_ATTESTATION_REPORT_SIZE];
    unsigned char cecAttestationReport[NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE];
} nvmlConfComputeGpuAttestationReport_t;

typedef void* nvmlDevice_t;
typedef int   nvmlReturn_t;


typedef enum nvmlInforomObject_enum
{
    NVML_INFOROM_OEM            = 0,       //!< An object defined by OEM
    NVML_INFOROM_ECC            = 1,       //!< The ECC object determining the level of ECC support
    NVML_INFOROM_POWER          = 2,       //!< The power management object

    // Keep this last
    NVML_INFOROM_COUNT                     //!< This counts the number of infoROM objects the driver knows about
} nvmlInforomObject_t;

// ---------------------------------------------------------------------------
// X-macro table: X(Name, ReturnType, ParamDecls, CallArgs, NvmlSymbol)
// ---------------------------------------------------------------------------
#define NVML_FN_TABLE(X) \
    X(Init,     nvmlReturn_t, (void),                                                                     (),           nvmlInit) \
    X(Shutdown, nvmlReturn_t, (void),                                                                     (),           nvmlShutdown) \
    X(ErrStr,   const char*,  (nvmlReturn_t r),                                                           (r),          nvmlErrorString) \
    X(GetCount, nvmlReturn_t, (unsigned int *n),                                                          (n),          nvmlDeviceGetCount) \
    X(GetHandle,nvmlReturn_t, (unsigned int i, nvmlDevice_t *d),                                          (i, d),       nvmlDeviceGetHandleByIndex) \
    X(GetName,  nvmlReturn_t, (nvmlDevice_t d, char *b, unsigned int l),                                  (d, b, l),    nvmlDeviceGetName) \
    X(GetVbios, nvmlReturn_t, (nvmlDevice_t d, char *b, unsigned int l),                                  (d, b, l),    nvmlDeviceGetVbiosVersion) \
    X(GetDriver,nvmlReturn_t, (char *b, unsigned int l),                                                  (b, l),       nvmlSystemGetDriverVersion) \
    X(DeviceGetConfComputeGpuCertificate, nvmlReturn_t, (nvmlDevice_t d, nvmlConfComputeGpuCertificate_t *c), (d, c),  nvmlDeviceGetConfComputeGpuCertificate) \
    X(DeviceGetUUID, nvmlReturn_t, (nvmlDevice_t d, char *b),                                             (d, b),       nvmlDeviceGetUUID) \
    X(DeviceGetInforomVersion, nvmlReturn_t, (nvmlDevice_t device, nvmlInforomObject_t object, char *version, unsigned int length), (device, object, version, length), nvmlDeviceGetInforomVersion) \
    X(DeviceGetInforomImageVersion, nvmlReturn_t, (nvmlDevice_t device, char *version, unsigned int length), (device, version, length), nvmlDeviceGetInforomImageVersion) \
    X(DeviceGetInforomConfigurationChecksum , nvmlReturn_t, (nvmlDevice_t device, char *checksum), (device, checksum), nvmlDeviceGetInforomConfigurationChecksum ) \
    X(DeviceGetConfComputeGpuAttestationReport, nvmlReturn_t ,(nvmlDevice_t device, nvmlConfComputeGpuAttestationReport_t* gpuAtstReport), (device, gpuAtstReport), nvmlDeviceGetConfComputeGpuAttestationReport) \
	X(DeviceGetGspFirmwareVersion, nvmlReturn_t, (nvmlDevice_t device, char *version), (device, version), nvmlDeviceGetGspFirmwareVersion) \
    X(DeviceGetGspFirmwareMode, nvmlReturn_t, (nvmlDevice_t device, unsigned int *isEnabled, unsigned int *defaultMode), (device, isEnabled, defaultMode), nvmlDeviceGetGspFirmwareMode) \
    X(DeviceValidateInforom, nvmlReturn_t, (nvmlDevice_t device), (device), nvmlDeviceValidateInforom) \
    X(DeviceGetMigMode, nvmlReturn_t, (nvmlDevice_t device, unsigned int *currentMode, unsigned int *pendingMode), (device, currentMode, pendingMode), nvmlDeviceGetMigMode)

#define _TYPEDEF(Name, Ret, Params, Args, Sym)  typedef Ret (*fn_##Name) Params;
#define _STATIC( Name, Ret, Params, Args, Sym)  static fn_##Name _##Name = NULL;
#define _WRAP(Name, Ret, Params, Args, Sym)  \
    static Ret wrap_##Name Params {          \
        if (!_##Name) {                      \
            fprintf(stderr, "FATAL ERROR: NVML function symbol '%s' could not be resolved from libnvidia-ml.so (driver may be too old).\n", #Sym); \
            abort();                         \
        }                                    \
        return _##Name Args;                 \
    }

NVML_FN_TABLE(_TYPEDEF)

static void *_lib = NULL;
NVML_FN_TABLE(_STATIC)

NVML_FN_TABLE(_WRAP)

static const char* nvml_open(void) {
    _lib = dlopen("libnvidia-ml.so.1", RTLD_LAZY | RTLD_GLOBAL);
    if (!_lib) _lib = dlopen("libnvidia-ml.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!_lib) return dlerror();

    #define _LOAD(Name, Ret, Params, Args, Sym)  _##Name = (fn_##Name) dlsym(_lib, #Sym);
    NVML_FN_TABLE(_LOAD)
    #undef _LOAD

    return NULL;
}
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// nvmlInitErr records why NVML could not be loaded. It is reported by Nvidia.Init
// rather than at package initialization time, where it cannot be returned.
var nvmlInitErr error

func init() {
	if cerr := C.nvml_open(); cerr != nil {
		nvmlInitErr = fmt.Errorf("dlopen libnvidia-ml: %s", C.GoString(cerr))
		return
	}

	if err := nvmlCheck(C.wrap_Init()); err != nil {
		nvmlInitErr = fmt.Errorf("nvmlInit: %w", err)
	}
}

type DeviceHandle struct {
	handle C.nvmlDevice_t
}

func nvmlCheck(ret C.nvmlReturn_t) error {
	if ret == C.NVML_SUCCESS {
		return nil
	}
	return errors.New(C.GoString(C.wrap_ErrStr(ret)))
}

func QueryGPUAttestationReport(device *DeviceHandle, nonce []byte) ([]byte, error) {

	if device == nil {
		return nil, errors.New("device handle cannot be nil")
	}

	var attReport C.nvmlConfComputeGpuAttestationReport_t
	const nonceSize = len(attReport.nonce)

	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("provided nonce size (%d) does not match required size (%d)", len(nonce), nonceSize)
	}

	cNonceSlice := unsafe.Slice((*byte)(unsafe.Pointer(&attReport.nonce[0])), nonceSize)
	copy(cNonceSlice, nonce)

	err := nvmlCheck(C.wrap_DeviceGetConfComputeGpuAttestationReport(device.handle, &attReport))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation report: %w", err)
	}

	reportSize := int(attReport.attestationReportSize)
	if reportSize <= 0 || reportSize > len(attReport.attestationReport) {
		return nil, errors.New("fetched attestation report size is invalid or empty")
	}

	cSlice := unsafe.Slice((*byte)(unsafe.Pointer(&attReport.attestationReport[0])), reportSize)
	reportBytes := make([]byte, reportSize)
	copy(reportBytes, cSlice)

	return reportBytes, nil
}

func QueryUUID(device C.nvmlDevice_t) (string, error) {
	uuidb := (*C.char)(C.malloc(C.NVML_DEVICE_UUID_V2_BUFFER_SIZE))
	defer C.free(unsafe.Pointer(uuidb))
	if err := nvmlCheck(C.wrap_DeviceGetUUID(device, uuidb)); err != nil {
		return "", fmt.Errorf("nvmlDeviceGetUUID: %w", err)
	}
	return C.GoString(uuidb), nil
}

func QueryNonAttestationReportMeasurements(dev *DeviceHandle) (internal.NvidiaDeviceUnsignedEvidence, error) {
	if dev == nil {
		return internal.NvidiaDeviceUnsignedEvidence{}, errors.New("device handle cannot be nil")
	}
	device := dev.handle

	uuid, err := QueryUUID(device)
	if err != nil {
		return internal.NvidiaDeviceUnsignedEvidence{}, err
	}

	oemVersion, _ := QueryInfoROMVersion(device, internal.INFOROM_OEM)
	eccVersion, _ := QueryInfoROMVersion(device, internal.INFOROM_ECC)
	powerVersion, _ := QueryInfoROMVersion(device, internal.INFOROM_POWER)
	inforomImageVersion, _ := QueryInfoROMImageVersion(device)
	inforomConfigChecksum, _ := QueryInfoROMConfigChecksum(device)

	// Additional Queries derived from description
	gspFirmwareVersion, _ := QueryGspFirmwareVersion(device)
	gspEnabled, gspDefault, _ := QueryGspFirmwareMode(device)
	inforomValid := ValidateInfoROM(device) == nil
	migCurrent, migPending, _ := QueryMigMode(device)

	return internal.NvidiaDeviceUnsignedEvidence{
		UUID:                  uuid,
		InforomOemVersion:     oemVersion,
		InforomPowerVersion:   powerVersion,
		InforomEccVersion:     eccVersion,
		InforomImageVersion:   inforomImageVersion,
		InforomConfigChecksum: inforomConfigChecksum,

		// Added structural fields (Make sure these exist in your internal schema definition)
		GspFirmwareVersion:   gspFirmwareVersion,
		GspFirmwareIsEnabled: gspEnabled,
		GspFirmwareDefault:   gspDefault,
		InforomIsValid:       inforomValid,
		MigCurrentMode:       migCurrent,
		MigPendingMode:       migPending,
	}, nil
}

func QueryInfoROMVersion(device C.nvmlDevice_t, obj internal.InforomObject) (string, error) {
	var buf [C.NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE]byte
	ret := C.wrap_DeviceGetInforomVersion(device, C.nvmlInforomObject_t(obj), (*C.char)(unsafe.Pointer(&buf[0])), C.NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE)
	if ret != C.NVML_SUCCESS {
		return "", fmt.Errorf("nvmlDeviceGetInforomVersion: %w", nvmlCheck(ret))
	}
	n := bytes.IndexByte(buf[:], 0)
	if n == -1 {
		return string(buf[:]), nil
	}
	return string(buf[:n]), nil
}

func QueryInfoROMImageVersion(device C.nvmlDevice_t) (string, error) {
	var buf [C.NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE]byte
	ret := C.wrap_DeviceGetInforomImageVersion(device, (*C.char)(unsafe.Pointer(&buf[0])), C.NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE)
	if ret != C.NVML_SUCCESS {
		return "", fmt.Errorf("nvmlDeviceGetInforomImageVersion: %w", nvmlCheck(ret))
	}
	n := bytes.IndexByte(buf[:], 0)
	if n == -1 {
		return string(buf[:]), nil
	}
	return string(buf[:n]), nil
}

func QueryInfoROMConfigChecksum(device C.nvmlDevice_t) (string, error) {
	var buf [C.NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE]byte
	ret := C.wrap_DeviceGetInforomConfigurationChecksum(device, (*C.char)(unsafe.Pointer(&buf[0])))
	if ret != C.NVML_SUCCESS {
		return "", fmt.Errorf("nvmlDeviceGetInforomConfigurationChecksum: %w", nvmlCheck(ret))
	}
	n := bytes.IndexByte(buf[:], 0)
	if n == -1 {
		return string(buf[:]), nil
	}
	return string(buf[:n]), nil
}

// ===========================================================================
// Added Supplementary Functions
// ===========================================================================

// QueryGspFirmwareVersion fetches the GSP firmware version string
func QueryGspFirmwareVersion(device C.nvmlDevice_t) (string, error) {
	var buf [C.NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE]byte // Reusing 16-byte buffer size typically standard for versions
	ret := C.wrap_DeviceGetGspFirmwareVersion(device, (*C.char)(unsafe.Pointer(&buf[0])))
	if ret != C.NVML_SUCCESS {
		return "", fmt.Errorf("nvmlDeviceGetGspFirmwareVersion: %w", nvmlCheck(ret))
	}
	n := bytes.IndexByte(buf[:], 0)
	if n == -1 {
		return string(buf[:]), nil
	}
	return string(buf[:n]), nil
}

// QueryGspFirmwareMode queries whether GSP mode is active and if it's default
func QueryGspFirmwareMode(device C.nvmlDevice_t) (bool, bool, error) {
	var isEnabled C.uint
	var defaultMode C.uint
	ret := C.wrap_DeviceGetGspFirmwareMode(device, &isEnabled, &defaultMode)
	if ret != C.NVML_SUCCESS {
		return false, false, fmt.Errorf("nvmlDeviceGetGspFirmwareMode: %w", nvmlCheck(ret))
	}
	return isEnabled != 0, defaultMode != 0, nil
}

// ValidateInfoROM parses and runs checksum testing directly on the flash hardware layer
func ValidateInfoROM(device C.nvmlDevice_t) error {
	ret := C.wrap_DeviceValidateInforom(device)
	if ret != C.NVML_SUCCESS {
		return fmt.Errorf("nvmlDeviceValidateInforom: %w", nvmlCheck(ret))
	}
	return nil
}

// QueryMigMode retrieves the running state and configurations of Multi-Instance GPU architecture
func QueryMigMode(device C.nvmlDevice_t) (uint32, uint32, error) {
	var currentMode C.uint
	var pendingMode C.uint
	ret := C.wrap_DeviceGetMigMode(device, &currentMode, &pendingMode)
	if ret != C.NVML_SUCCESS {
		return 0, 0, fmt.Errorf("nvmlDeviceGetMigMode: %w", nvmlCheck(ret))
	}
	return uint32(currentMode), uint32(pendingMode), nil
}

func QueryGPUCertificate(device *DeviceHandle) (string, error) {

	if device == nil {
		return "", errors.New("device handle cannot be nil")
	}

	var certStruct C.nvmlConfComputeGpuCertificate_t
	if err := nvmlCheck(C.wrap_DeviceGetConfComputeGpuCertificate(device.handle, &certStruct)); err != nil {
		return "", fmt.Errorf("nvmlDeviceGetConfComputeGpuCertificate: %w", err)
	}
	cBuf := unsafe.Slice((*byte)(unsafe.Pointer(&certStruct.attestationCertChain[0])), len(certStruct.attestationCertChain))

	n := bytes.IndexByte(cBuf, 0)
	if n == -1 {
		return string(cBuf), nil
	}

	return string(cBuf[:n]), nil
}

func GetHandle(i int) (*DeviceHandle, error) {
	var handle C.nvmlDevice_t

	if err := nvmlCheck(C.wrap_GetHandle(C.uint(i), &handle)); err != nil {
		log.Infof("error fetching device handle for gpu %d : %s", i, err)
		return nil, fmt.Errorf("nvmlDeviceGetHandleByIndex(%d): %w", i, err)
	}

	return &DeviceHandle{handle: handle}, nil
}

// QueryGPUs opens libnvidia-ml.so at runtime via dlopen and returns info for
// every installed GPU.
func QueryGPUs() ([]GPUInfo, error) {

	// Driver version is system-wide.
	driverBuf := (*C.char)(C.malloc(C.NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE))
	defer C.free(unsafe.Pointer(driverBuf))
	if err := nvmlCheck(C.wrap_GetDriver(driverBuf, C.NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE)); err != nil {
		return nil, fmt.Errorf("nvmlSystemGetDriverVersion: %w", err)
	}
	driver := C.GoString(driverBuf)

	var count C.uint
	if err := nvmlCheck(C.wrap_GetCount(&count)); err != nil {
		return nil, fmt.Errorf("nvmlDeviceGetCount: %w", err)
	}

	gpus := make([]GPUInfo, 0, int(count))

	for i := range uint(count) {
		var handle C.nvmlDevice_t
		if err := nvmlCheck(C.wrap_GetHandle(C.uint(i), &handle)); err != nil {
			return nil, fmt.Errorf("nvmlDeviceGetHandleByIndex(%d): %w", i, err)
		}

		cert, err := QueryGPUCertificate(&DeviceHandle{handle})
		if err != nil {
			return nil, fmt.Errorf("fetching gpu certs failed")
		}

		nameBuf := (*C.char)(C.malloc(C.NVML_DEVICE_NAME_BUFFER_SIZE))
		defer C.free(unsafe.Pointer(nameBuf))
		if err := nvmlCheck(C.wrap_GetName(handle, nameBuf, C.NVML_DEVICE_NAME_BUFFER_SIZE)); err != nil {
			return nil, fmt.Errorf("nvmlDeviceGetName(%d): %w", i, err)
		}

		vbiosBuf := (*C.char)(C.malloc(C.NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE))
		defer C.free(unsafe.Pointer(vbiosBuf))
		if err := nvmlCheck(C.wrap_GetVbios(handle, vbiosBuf, C.NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE)); err != nil {
			return nil, fmt.Errorf("nvmlDeviceGetVbiosVersion(%d): %w", i, err)
		}

		uuid, err := QueryUUID(handle)
		if err != nil {
			return nil, fmt.Errorf("failed to query uuid: %w", err)
		}

		gpus = append(gpus, GPUInfo{
			Index:         i,
			DeviceName:    C.GoString(nameBuf),
			DeviceUUID:    uuid,
			DriverVersion: driver,
			VBIOSVersion:  C.GoString(vbiosBuf),
			certs:         cert,
		})

	}

	return gpus, nil
}
