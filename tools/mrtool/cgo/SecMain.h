/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include <openssl/sha.h>
#include "PiHob.h"

#pragma pack(1)
typedef struct {
  EFI_HOB_GUID_TYPE    GuidHeader;
  UINT16               HostBridgeDevId;

  UINT64               PcdConfidentialComputingGuestAttr;
  BOOLEAN              SevEsIsEnabled;

  UINT32               BootMode;
  BOOLEAN              S3Supported;

  BOOLEAN              SmmSmramRequire;
  BOOLEAN              Q35SmramAtDefaultSmbase;
  UINT16               Q35TsegMbytes;

  UINT64               FirstNonAddress;
  UINT8                PhysMemAddressWidth;
  UINT32               Uc32Base;
  UINT32               Uc32Size;

  BOOLEAN              PcdSetNxForStack;
  UINT64               PcdTdxSharedBitMask;

  UINT64               PcdPciMmio64Base;
  UINT64               PcdPciMmio64Size;
  UINT32               PcdPciMmio32Base;
  UINT32               PcdPciMmio32Size;
  UINT64               PcdPciIoBase;
  UINT64               PcdPciIoSize;

  UINT64               PcdEmuVariableNvStoreReserved;
  UINT32               PcdCpuBootLogicalProcessorNumber;
  UINT32               PcdCpuMaxLogicalProcessorNumber;
  UINT32               DefaultMaxCpuNumber;

  UINT32               S3AcpiReservedMemoryBase;
  UINT32               S3AcpiReservedMemorySize;
} EFI_HOB_PLATFORM_INFO;
#pragma pack()

uint8_t *
extract_lzma_fvmain_new (EFI_FIRMWARE_VOLUME_HEADER  *Fv, size_t *extracted_size);