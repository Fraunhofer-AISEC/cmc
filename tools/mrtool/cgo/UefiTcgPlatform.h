/** @file
  TCG EFI Platform Definition in TCG_EFI_Platform_1_20_Final and
  TCG PC Client Platform Firmware Profile Specification, Revision 1.06

  Copyright (c) 2006 - 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __UEFI_TCG_PLATFORM_H__
#define __UEFI_TCG_PLATFORM_H__

#include "UefiBaseType.h"

typedef UINT32        TCG_EVENTTYPE;

//
// Standard event types
//
#define EV_PREBOOT_CERT             ((TCG_EVENTTYPE) 0x00000000)
#define EV_POST_CODE                ((TCG_EVENTTYPE) 0x00000001)
#define EV_NO_ACTION                ((TCG_EVENTTYPE) 0x00000003)
#define EV_SEPARATOR                ((TCG_EVENTTYPE) 0x00000004)
#define EV_ACTION                   ((TCG_EVENTTYPE) 0x00000005)
#define EV_EVENT_TAG                ((TCG_EVENTTYPE) 0x00000006)
#define EV_S_CRTM_CONTENTS          ((TCG_EVENTTYPE) 0x00000007)
#define EV_S_CRTM_VERSION           ((TCG_EVENTTYPE) 0x00000008)
#define EV_CPU_MICROCODE            ((TCG_EVENTTYPE) 0x00000009)
#define EV_PLATFORM_CONFIG_FLAGS    ((TCG_EVENTTYPE) 0x0000000A)
#define EV_TABLE_OF_DEVICES         ((TCG_EVENTTYPE) 0x0000000B)
#define EV_COMPACT_HASH             ((TCG_EVENTTYPE) 0x0000000C)
#define EV_NONHOST_CODE             ((TCG_EVENTTYPE) 0x0000000F)
#define EV_NONHOST_CONFIG           ((TCG_EVENTTYPE) 0x00000010)
#define EV_NONHOST_INFO             ((TCG_EVENTTYPE) 0x00000011)
#define EV_OMIT_BOOT_DEVICE_EVENTS  ((TCG_EVENTTYPE) 0x00000012)

//
// EFI specific event types
//
#define EV_EFI_EVENT_BASE                 ((TCG_EVENTTYPE) 0x80000000)
#define EV_EFI_VARIABLE_DRIVER_CONFIG     (EV_EFI_EVENT_BASE + 1)
#define EV_EFI_VARIABLE_BOOT              (EV_EFI_EVENT_BASE + 2)
#define EV_EFI_BOOT_SERVICES_APPLICATION  (EV_EFI_EVENT_BASE + 3)
#define EV_EFI_BOOT_SERVICES_DRIVER       (EV_EFI_EVENT_BASE + 4)
#define EV_EFI_RUNTIME_SERVICES_DRIVER    (EV_EFI_EVENT_BASE + 5)
#define EV_EFI_GPT_EVENT                  (EV_EFI_EVENT_BASE + 6)
#define EV_EFI_ACTION                     (EV_EFI_EVENT_BASE + 7)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB     (EV_EFI_EVENT_BASE + 8)
#define EV_EFI_HANDOFF_TABLES             (EV_EFI_EVENT_BASE + 9)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB2    (EV_EFI_EVENT_BASE + 0xA)
#define EV_EFI_HANDOFF_TABLES2            (EV_EFI_EVENT_BASE + 0xB)
#define EV_EFI_HCRTM_EVENT                (EV_EFI_EVENT_BASE + 0x10)
#define EV_EFI_VARIABLE_AUTHORITY         (EV_EFI_EVENT_BASE + 0xE0)
#define EV_EFI_SPDM_FIRMWARE_BLOB         (EV_EFI_EVENT_BASE + 0xE1)
#define EV_EFI_SPDM_FIRMWARE_CONFIG       (EV_EFI_EVENT_BASE + 0xE2)
#define EV_EFI_SPDM_DEVICE_BLOB           EV_EFI_SPDM_FIRMWARE_BLOB
#define EV_EFI_SPDM_DEVICE_CONFIG         EV_EFI_SPDM_FIRMWARE_CONFIG

#define EFI_CALLING_EFI_APPLICATION         \
  "Calling EFI Application from Boot Option"
#define EFI_RETURNING_FROM_EFI_APPLICATION  \
  "Returning from EFI Application from Boot Option"
#define EFI_EXIT_BOOT_SERVICES_INVOCATION   \
  "Exit Boot Services Invocation"
#define EFI_EXIT_BOOT_SERVICES_FAILED       \
  "Exit Boot Services Returned with Failure"
#define EFI_EXIT_BOOT_SERVICES_SUCCEEDED    \
  "Exit Boot Services Returned with Success"


typedef struct {
  CHAR16      *VariableName;
  EFI_GUID    *VendorGuid;
} VARIABLE_TYPE;

#pragma pack (1)

///
/// UEFI_VARIABLE_DATA
///
/// This structure serves as the header for measuring variables. The name of the
/// variable (in Unicode format) should immediately follow, then the variable
/// data.
/// This is defined in TCG PC Client Firmware Profile Spec 00.21
///
typedef struct tdUEFI_VARIABLE_DATA {
  EFI_GUID    VariableName;
  UINT64      UnicodeNameLength;
  UINT64      VariableDataLength;
  CHAR16      UnicodeName[1];
  INT8        VariableData[1];                        ///< Driver or platform-specific data
} UEFI_VARIABLE_DATA;

#pragma pack ()

#endif
