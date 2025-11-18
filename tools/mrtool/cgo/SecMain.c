/** @file
  Main SEC phase code.  Transitions to PEI.

  Copyright (c) 2008 - 2015, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2020, Advanced Micro Devices, Inc. All rights reserved.<BR>

  Copyright (c) 2022, Fraunhofer AISEC
  Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.<BR>

  This is a strongly modified version of the original file. The purpose
  is to measure the OVMF PEI Firmware Volume as well as the OVMF DXE
  Firmware Volume to pre-calculate the hashes which are expected to be
  extended into the TPM PCR0 during a measured boot.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "LzmaDec.h"

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "PiFirmwareVolume.h"
#include "LzmaDecompressLibInternal.h"
#include "SecMain.h"

#define DEBUG(...)  do {} while (0)

#define EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE  0x0B

#define EFI_SECTION_COMPRESSION   0x01
#define EFI_SECTION_GUID_DEFINED  0x02
#define EFI_SECTION_FIRMWARE_VOLUME_IMAGE  0x17

#define SECTION2_SIZE(SectionHeaderPtr) \
    (((EFI_COMMON_SECTION_HEADER2 *) (UINTN) SectionHeaderPtr)->ExtendedSize)

#define IS_SECTION2(SectionHeaderPtr) \
    (SECTION_SIZE (SectionHeaderPtr) == 0x00ffffff)

typedef struct {
  ///
  /// This GUID is the file name. It is used to uniquely identify the file.
  ///
  EFI_GUID                   Name;
  ///
  /// Used to verify the integrity of the file.
  ///
  UINT16    IntegrityCheck;
  ///
  /// Identifies the type of file.
  ///
  UINT8            Type;
  ///
  /// Declares various file attribute bits.
  ///
  UINT8    Attributes;
  ///
  /// The length of the file in bytes, including the FFS header.
  ///
  UINT8                      Size[3];
  ///
  /// Used to track the state of the file throughout the life of the file from creation to deletion.
  ///
  UINT8         State;
} EFI_FFS_FILE_HEADER;

typedef struct {
  ///
  /// A 24-bit unsigned integer that contains the total size of the section in bytes,
  /// including the EFI_COMMON_SECTION_HEADER.
  ///
  UINT8               Size[3];

  UINT8    Type;

  ///
  /// If Size is 0xFFFFFF, then ExtendedSize contains the size of the section. If
  /// Size is not equal to 0xFFFFFF, then this field does not exist.
  ///
  UINT32              ExtendedSize;
} EFI_COMMON_SECTION_HEADER2;

///
/// The argument passed as the SectionHeaderPtr parameter to the SECTION_SIZE()
/// and IS_SECTION2() function-like macros below must not have side effects:
/// SectionHeaderPtr is evaluated multiple times.
///
#define SECTION_SIZE(SectionHeaderPtr)  ((UINT32) (\
    (((EFI_COMMON_SECTION_HEADER *) (UINTN) (SectionHeaderPtr))->Size[0]      ) | \
    (((EFI_COMMON_SECTION_HEADER *) (UINTN) (SectionHeaderPtr))->Size[1] <<  8) | \
    (((EFI_COMMON_SECTION_HEADER *) (UINTN) (SectionHeaderPtr))->Size[2] << 16)))

///
/// The argument passed as the FfsFileHeaderPtr parameter to the
/// FFS_FILE_SIZE() function-like macro below must not have side effects:
/// FfsFileHeaderPtr is evaluated multiple times.
///
#define FFS_FILE_SIZE(FfsFileHeaderPtr)  ((UINT32) (\
    (((EFI_FFS_FILE_HEADER *) (UINTN) (FfsFileHeaderPtr))->Size[0]      ) | \
    (((EFI_FFS_FILE_HEADER *) (UINTN) (FfsFileHeaderPtr))->Size[1] <<  8) | \
    (((EFI_FFS_FILE_HEADER *) (UINTN) (FfsFileHeaderPtr))->Size[2] << 16)))

EFI_GUID lzma_decrompress_guid = { 0xEE4E5898, 0x3914, 0x4259, { 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF }};
EFI_GUID ovmf_platform_info_hob_guid = {0xdec9b486, 0x1f16, 0x47c7, {0x8f, 0x68, 0xdf, 0x1a, 0x41, 0x88, 0x8b, 0xa5}};
EFI_GUID efi_firmware_ffs2_guid = { 0x8c8ce578, 0x8a3d, 0x4f1c, { 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3 }};

static bool
compare_guid(const GUID *g1, const GUID *g2)
{
    if (memcmp(g1->Data4, g2->Data4, sizeof(g1->Data4))) {
        return false;
    }

    return (g1->Data1 == g2->Data1 && g1->Data2 == g2->Data2 && g1->Data3 == g2->Data3);
}

EFI_STATUS
FindFfsSectionInstance (
  IN  VOID                       *Sections,
  IN  UINTN                      SizeOfSections,
  IN  UINT8           SectionType,
  IN  UINTN                      Instance,
  OUT EFI_COMMON_SECTION_HEADER  **FoundSection
  )
{
  EFI_PHYSICAL_ADDRESS       CurrentAddress;
  UINT32                     Size;
  EFI_PHYSICAL_ADDRESS       EndOfSections;
  EFI_COMMON_SECTION_HEADER  *Section;
  EFI_PHYSICAL_ADDRESS       EndOfSection;

  //
  // Loop through the FFS file sections within the PEI Core FFS file
  //
  EndOfSection  = (EFI_PHYSICAL_ADDRESS)(UINTN)Sections;
  EndOfSections = EndOfSection + SizeOfSections;
  for ( ; ;) {
    if (EndOfSection == EndOfSections) {
      break;
    }

    CurrentAddress = (EndOfSection + 3) & ~(3ULL);
    if (CurrentAddress >= EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    Section = (EFI_COMMON_SECTION_HEADER *)(UINTN)CurrentAddress;

    Size = SECTION_SIZE (Section);
    if (Size < sizeof (*Section)) {
      return EFI_VOLUME_CORRUPTED;
    }

    EndOfSection = CurrentAddress + Size;
    if (EndOfSection > EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Look for the requested section type
    //
    if (Section->Type == SectionType) {
      if (Instance == 0) {
        *FoundSection = Section;
        return EFI_SUCCESS;
      } else {
        Instance--;
      }
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
FindFfsSectionInSections (
  IN  VOID                       *Sections,
  IN  UINTN                      SizeOfSections,
  IN  UINT8           SectionType,
  OUT EFI_COMMON_SECTION_HEADER  **FoundSection
  )
{
  return FindFfsSectionInstance (
           Sections,
           SizeOfSections,
           SectionType,
           0,
           FoundSection
           );
}

int FindFfsFileAndSection (
    IN  EFI_FIRMWARE_VOLUME_HEADER  *Fv,
    IN  UINT8             FileType,
    IN  UINT8            SectionType,
    OUT EFI_COMMON_SECTION_HEADER   **FoundSection
    )
{
    EFI_STATUS            Status;
    EFI_PHYSICAL_ADDRESS  CurrentAddress;
    EFI_PHYSICAL_ADDRESS  EndOfFirmwareVolume;
    EFI_FFS_FILE_HEADER   *File;
    UINT32                Size;
    EFI_PHYSICAL_ADDRESS  EndOfFile;

    if (Fv->Signature != EFI_FVH_SIGNATURE) {
        DEBUG ("FV at %p does not have FV header signature\n", Fv);
        return -1;
    }

    CurrentAddress      = (EFI_PHYSICAL_ADDRESS)(UINTN)Fv;
    EndOfFirmwareVolume = CurrentAddress + Fv->FvLength;

    //
    // Loop through the FFS files in the Boot Firmware Volume
    //
    for (EndOfFile = CurrentAddress + Fv->HeaderLength; ; ) {
        CurrentAddress = (EndOfFile + 7) & ~(7ULL);
        if (CurrentAddress > EndOfFirmwareVolume) {
            DEBUG ("Address larger than end of FV\n");
            return -1;
        }

        File = (EFI_FFS_FILE_HEADER *)(UINTN)CurrentAddress;
        Size = FFS_FILE_SIZE (File);
        if (Size < (sizeof (*File) + sizeof (EFI_COMMON_SECTION_HEADER))) {
            DEBUG("Size smaller than header\n");
            return -1;
        }

        EndOfFile = CurrentAddress + Size;
        if (EndOfFile > EndOfFirmwareVolume) {
            DEBUG("End of file larger than end of FV\n");
            return -1;
        }

        //
        // Look for the request file type
        //
        if (File->Type != FileType) {
            continue;
        }

        Status = FindFfsSectionInSections (
                (VOID *)(File + 1),
                (UINTN)EndOfFile - (UINTN)(File + 1),
                SectionType,
                FoundSection
                );
        if (!EFI_ERROR (Status)) {
            DEBUG("FOUND FFS Section\n");
            return 0;
        } else if (Status == EFI_VOLUME_CORRUPTED) {
            DEBUG("EFI_VOLUME_CORRUPTED\n");
            return -1;
        }
    }
    DEBUG("Not found\n");
    return -1;
}

uint8_t *
extract_lzma_fvmain_new (EFI_FIRMWARE_VOLUME_HEADER  *Fv, size_t *extracted_size)
{
    EFI_GUID_DEFINED_SECTION *section;
    uint8_t *fvmain = NULL;

    int ret = FindFfsFileAndSection (
                Fv,
                EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE,
                EFI_SECTION_GUID_DEFINED,
                (EFI_COMMON_SECTION_HEADER **)&section
                );
    if (ret != 0) {
        DEBUG("Unable to find GUID defined section\n");
        return NULL;
    }

    uint32_t size =   (section->CommonHeader.Size[0] << 0) |
                        (section->CommonHeader.Size[1] << 8) |
                        (section->CommonHeader.Size[2] << 16);

    DEBUG("Section->DataOffset: %d\n", section->DataOffset);
    DEBUG("Section->CommonHeader.Type: %d\n", section->CommonHeader.Type);
    DEBUG("Section->CommonHeader.Size: %d (0x%x)\n", size, size);

    if (!compare_guid (
        &lzma_decrompress_guid,
        &(((EFI_GUID_DEFINED_SECTION *)section)->SectionDefinitionGuid)
        ))
    {
      printf("GUIDs do not match\n");
      return NULL;
    }

    UINT32 output_buf_size = 0;
    UINT32 scratch_buf_size = 0;

    ret = LzmaUefiDecompressGetInfo (
        (UINT8 *)section + ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
        SECTION_SIZE (section) - ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
        &output_buf_size,
        &scratch_buf_size);
    if (ret != 0) {
        printf("Failed to get LZMA GUIDed section info %d\n", ret);
        return NULL;
    }

    fvmain = (uint8_t *)malloc(output_buf_size);
    if (!fvmain) {
      printf("Failed to allocate memory\n");
      return NULL;
    }
    uint8_t *scratch_buf = (uint8_t *)malloc(scratch_buf_size);
    if (!scratch_buf) {
      printf("Failed to allocate memory\n");
      return NULL;
    }

    ret = LzmaUefiDecompress (
            (UINT8 *)section + ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
            SECTION_SIZE (section) - ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
            fvmain,
            scratch_buf);
    if (ret != 0) {
        printf("Failed to decompress LZMA compressed volume\n");
        return NULL;
    }

    *extracted_size = output_buf_size;

    DEBUG("Extracted FVMAIN_COMPACT.Fv\n");

    free(scratch_buf);
    return fvmain;
}

