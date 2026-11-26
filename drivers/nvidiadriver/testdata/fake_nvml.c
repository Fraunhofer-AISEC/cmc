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

// Fake libnvidia-ml.so for unit tests. Signatures and buffer sizes follow nvml.h. String getters
// fill the whole buffer NVML may write to, so that undersized buffers are caught with -asan.

#include <string.h>

#define NVML_SUCCESS                  0
#define NVML_ERROR_INVALID_ARGUMENT   2
#define NVML_ERROR_INSUFFICIENT_SIZE  7

#define NVML_DEVICE_NAME_BUFFER_SIZE            64
#define NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE   32
#define NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE  80
#define NVML_DEVICE_UUID_V2_BUFFER_SIZE         96
#define NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE 16
#define NVML_GSP_FIRMWARE_VERSION_BUF_SIZE      0x40
#define NVML_GPU_CERT_CHAIN_SIZE                0x1000
#define NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE    0x1400
#define NVML_CC_GPU_CEC_NONCE_SIZE              0x20
#define NVML_CC_GPU_ATTESTATION_REPORT_SIZE     0x2000
#define NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE 0x1000

#define FAKE_CHECKSUM    0x0badc0deu
#define FAKE_REPORT_SIZE 0x40
#define FAKE_CERT        "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"

typedef int nvmlReturn_t;
typedef void *nvmlDevice_t;

typedef struct {
    unsigned int  certChainSize;
    unsigned int  attestationCertChainSize;
    unsigned char certChain[NVML_GPU_CERT_CHAIN_SIZE];
    unsigned char attestationCertChain[NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE];
} nvmlConfComputeGpuCertificate_t;

typedef struct {
    unsigned int  isCecAttestationReportPresent;
    unsigned int  attestationReportSize;
    unsigned int  cecAttestationReportSize;
    unsigned char nonce[NVML_CC_GPU_CEC_NONCE_SIZE];
    unsigned char attestationReport[NVML_CC_GPU_ATTESTATION_REPORT_SIZE];
    unsigned char cecAttestationReport[NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE];
} nvmlConfComputeGpuAttestationReport_t;

static nvmlDevice_t fake_device = (nvmlDevice_t)&fake_device;

// fill zeroes the whole buffer and writes str, truncated to the buffer size.
static nvmlReturn_t fill(char *buf, unsigned int length, unsigned int required, const char *str) {
    if (length < required) return NVML_ERROR_INSUFFICIENT_SIZE;
    memset(buf, 0, length);
    strncpy(buf, str, length - 1);
    return NVML_SUCCESS;
}

static nvmlReturn_t check(nvmlDevice_t device) {
    return device == fake_device ? NVML_SUCCESS : NVML_ERROR_INVALID_ARGUMENT;
}

nvmlReturn_t nvmlInit_v2(void) { return NVML_SUCCESS; }

nvmlReturn_t nvmlShutdown(void) { return NVML_SUCCESS; }

const char *nvmlErrorString(nvmlReturn_t r) {
    switch (r) {
    case NVML_SUCCESS: return "Success";
    case NVML_ERROR_INVALID_ARGUMENT: return "Invalid Argument";
    case NVML_ERROR_INSUFFICIENT_SIZE: return "Insufficient Size";
    default: return "Unknown Error";
    }
}

nvmlReturn_t nvmlDeviceGetCount_v2(unsigned int *n) {
    *n = 1;
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetHandleByIndex_v2(unsigned int i, nvmlDevice_t *d) {
    if (i != 0) return NVML_ERROR_INVALID_ARGUMENT;
    *d = fake_device;
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetName(nvmlDevice_t d, char *b, unsigned int l) {
    if (check(d)) return check(d);
    return fill(b, l, NVML_DEVICE_NAME_BUFFER_SIZE, "NVIDIA H100 NVL");
}

nvmlReturn_t nvmlDeviceGetVbiosVersion(nvmlDevice_t d, char *b, unsigned int l) {
    if (check(d)) return check(d);
    return fill(b, l, NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE, "96.00.A5.00.01");
}

nvmlReturn_t nvmlSystemGetDriverVersion(char *b, unsigned int l) {
    return fill(b, l, NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE, "595.71.05");
}

nvmlReturn_t nvmlDeviceGetUUID(nvmlDevice_t d, char *b, unsigned int l) {
    if (check(d)) return check(d);
    return fill(b, l, NVML_DEVICE_UUID_V2_BUFFER_SIZE, "GPU-01234567-89ab-cdef-0123-456789abcdef");
}

nvmlReturn_t nvmlDeviceGetInforomVersion(nvmlDevice_t d, int object, char *b, unsigned int l) {
    static const char *versions[] = {"G520.0200.00.05", "7.0", "N/A"};
    if (check(d)) return check(d);
    if (object < 0 || object > 2) return NVML_ERROR_INVALID_ARGUMENT;
    return fill(b, l, NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE, versions[object]);
}

nvmlReturn_t nvmlDeviceGetInforomImageVersion(nvmlDevice_t d, char *b, unsigned int l) {
    if (check(d)) return check(d);
    return fill(b, l, NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE, "G520.0200.00.04");
}

nvmlReturn_t nvmlDeviceGetInforomConfigurationChecksum(nvmlDevice_t d, unsigned int *checksum) {
    if (check(d)) return check(d);
    *checksum = FAKE_CHECKSUM;
    return NVML_SUCCESS;
}

// The GSP firmware version buffer has no length parameter, so fill all of it.
nvmlReturn_t nvmlDeviceGetGspFirmwareVersion(nvmlDevice_t d, char *version) {
    if (check(d)) return check(d);
    memset(version, 'g', NVML_GSP_FIRMWARE_VERSION_BUF_SIZE - 1);
    version[NVML_GSP_FIRMWARE_VERSION_BUF_SIZE - 1] = '\0';
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetGspFirmwareMode(nvmlDevice_t d, unsigned int *isEnabled, unsigned int *defaultMode) {
    if (check(d)) return check(d);
    *isEnabled = 1;
    *defaultMode = 1;
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceValidateInforom(nvmlDevice_t d) {
    return check(d);
}

nvmlReturn_t nvmlDeviceGetMigMode(nvmlDevice_t d, unsigned int *currentMode, unsigned int *pendingMode) {
    if (check(d)) return check(d);
    *currentMode = 0;
    *pendingMode = 1;
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetConfComputeGpuCertificate(nvmlDevice_t d, nvmlConfComputeGpuCertificate_t *c) {
    if (check(d)) return check(d);
    memset(c, 0, sizeof(*c));
    c->attestationCertChainSize = sizeof(FAKE_CERT) - 1;
    memcpy(c->attestationCertChain, FAKE_CERT, sizeof(FAKE_CERT) - 1);
    return NVML_SUCCESS;
}

// The fake report is the nonce repeated to FAKE_REPORT_SIZE bytes.
nvmlReturn_t nvmlDeviceGetConfComputeGpuAttestationReport(nvmlDevice_t d, nvmlConfComputeGpuAttestationReport_t *r) {
    if (check(d)) return check(d);
    r->isCecAttestationReportPresent = 0;
    r->attestationReportSize = FAKE_REPORT_SIZE;
    r->cecAttestationReportSize = 0;
    for (int i = 0; i < FAKE_REPORT_SIZE; i++) {
        r->attestationReport[i] = r->nonce[i % NVML_CC_GPU_CEC_NONCE_SIZE];
    }
    return NVML_SUCCESS;
}
