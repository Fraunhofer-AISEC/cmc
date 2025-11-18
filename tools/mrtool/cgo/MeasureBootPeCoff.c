/** @file
  This module implements measuring PeCoff image for Tcg2 Protocol.

  Caution: This file requires additional review when modified.
  This driver will have external input - PE/COFF image.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>

  Copyright (c) 2022, Fraunhofer AISEC
  Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.<BR>

  This is a strongly modified version of the original file. Its purpose is
  to measure the kernel PE/COFF image and precompute the hash which is
  expected to be extended into theTPM PCR4 during a measured boot.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/ssl.h>

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "MeasureBootPeCoff.h"

bool DebugOutput = false;

void SetDebug() {
    DebugOutput = true;
}

#define DEBUG(fmt, ...)                                                                            \
    do {                                                                                           \
        if (DebugOutput)                                                                           \
            printf(fmt, ##__VA_ARGS__);                                                            \
    } while (0)

UINTN  mTcg2DxeImageSize = 0;

/**
  Reads contents of a PE/COFF image in memory buffer.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will make sure the PE/COFF image content
  read is within the image buffer.

  @param  FileHandle      Pointer to the file handle to read the PE/COFF image.
  @param  FileOffset      Offset into the PE/COFF image to begin the read operation.
  @param  ReadSize        On input, the size in bytes of the requested read operation.
                          On output, the number of bytes actually read.
  @param  Buffer          Output buffer that contains the data read from the PE/COFF image.

  @retval EFI_SUCCESS     The specified portion of the PE/COFF image was read and the size
**/
EFI_STATUS
EFIAPI
Tcg2DxeImageRead (
  IN     VOID    *FileHandle,
  IN     UINTN   FileOffset,
  IN OUT UINTN   *ReadSize,
  OUT    VOID    *Buffer
  )
{
  UINTN               EndPosition;

  if (FileHandle == NULL || ReadSize == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (MAX_ADDRESS - FileOffset < *ReadSize) {
    return EFI_INVALID_PARAMETER;
  }

  EndPosition = FileOffset + *ReadSize;
  if (EndPosition > mTcg2DxeImageSize) {
    *ReadSize = (UINT32)(mTcg2DxeImageSize - FileOffset);
  }

  if (FileOffset >= mTcg2DxeImageSize) {
    *ReadSize = 0;
  }

  memcpy (Buffer, (UINT8 *)((UINTN) FileHandle + FileOffset), *ReadSize);

  return EFI_SUCCESS;
}

/**
  Adjust some fields in section header for TE image.

  @param  SectionHeader             Pointer to the section header.
  @param  TeStrippedOffset          Size adjust for the TE image.

**/
VOID
PeCoffLoaderAdjustOffsetForTeImage (
  EFI_IMAGE_SECTION_HEADER              *SectionHeader,
  UINT32                                TeStrippedOffset
  )
{
  SectionHeader->VirtualAddress   -= TeStrippedOffset;
  SectionHeader->PointerToRawData -= TeStrippedOffset;
}

BOOLEAN
PeCoffLoaderImageFormatSupported (
  IN  UINT16  Machine
  )
{
  if ((Machine == IMAGE_FILE_MACHINE_I386) || (Machine == IMAGE_FILE_MACHINE_X64) ||
      (Machine == IMAGE_FILE_MACHINE_EBC) || (Machine == IMAGE_FILE_MACHINE_ARM64)) {
    return TRUE;
  }

  return FALSE;
}

/**
  Retrieves the PE or TE Header from a PE/COFF or TE image.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this routine will
  also done many checks in PE image to make sure PE image DosHeader, PeOptionHeader,
  SizeOfHeader, Section Data Region and Security Data Region be in PE image range.

  @param  ImageContext    The context of the image being loaded.
  @param  Hdr             The buffer in which to return the PE32, PE32+, or TE header.

  @retval RETURN_SUCCESS  The PE or TE Header is read.
  @retval Other           The error status from reading the PE/COFF or TE image using the ImageRead function.

**/
RETURN_STATUS
PeCoffLoaderGetPeHeader (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT         *ImageContext,
  OUT    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr
  )
{
  RETURN_STATUS         Status;
  EFI_IMAGE_DOS_HEADER  DosHdr;
  UINTN                 Size;
  UINTN                 ReadSize;
  UINT32                SectionHeaderOffset;
  UINT32                Index;
  UINT32                HeaderWithoutDataDir;
  CHAR8                 BufferData;
  UINTN                 NumberOfSections;
  EFI_IMAGE_SECTION_HEADER  SectionHeader;

  //
  // Read the DOS image header to check for its existence
  //
  Size = sizeof (EFI_IMAGE_DOS_HEADER);
  ReadSize = Size;
  Status = ImageContext->ImageRead (
                           ImageContext->Handle,
                           0,
                           &Size,
                           &DosHdr
                           );
  if (RETURN_ERROR (Status) || (Size != ReadSize)) {
    ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
    if (Size != ReadSize) {
      Status = RETURN_UNSUPPORTED;
    }
    return Status;
  }

  ImageContext->PeCoffHeaderOffset = 0;
  if (DosHdr.e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    //
    // DOS image header is present, so read the PE header after the DOS image
    // header
    //
    ImageContext->PeCoffHeaderOffset = DosHdr.e_lfanew;
  }

  //
  // Read the PE/COFF Header. For PE32 (32-bit) this will read in too much
  // data, but that should not hurt anything. Hdr.Pe32->OptionalHeader.Magic
  // determines if this is a PE32 or PE32+ image. The magic is in the same
  // location in both images.
  //
  Size = sizeof (EFI_IMAGE_OPTIONAL_HEADER_UNION);
  ReadSize = Size;
  Status = ImageContext->ImageRead (
                           ImageContext->Handle,
                           ImageContext->PeCoffHeaderOffset,
                           &Size,
                           Hdr.Pe32
                           );
  if (RETURN_ERROR (Status) || (Size != ReadSize)) {
    ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
    if (Size != ReadSize) {
      Status = RETURN_UNSUPPORTED;
    }
    return Status;
  }

  //
  // Use Signature to figure out if we understand the image format
  //
  if (Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) {
    ImageContext->IsTeImage         = TRUE;
    ImageContext->Machine           = Hdr.Te->Machine;
    ImageContext->ImageType         = (UINT16)(Hdr.Te->Subsystem);
    //
    // For TeImage, SectionAlignment is undefined to be set to Zero
    // ImageSize can be calculated.
    //
    ImageContext->ImageSize         = 0;
    ImageContext->SectionAlignment  = 0;
    ImageContext->SizeOfHeaders     = sizeof (EFI_TE_IMAGE_HEADER) + (UINTN)Hdr.Te->BaseOfCode - (UINTN)Hdr.Te->StrippedSize;

    //
    // Check the StrippedSize.
    //
    if (sizeof (EFI_TE_IMAGE_HEADER) >= (UINT32)Hdr.Te->StrippedSize) {
      ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
      return RETURN_UNSUPPORTED;
    }

    //
    // Check the SizeOfHeaders field.
    //
    if (Hdr.Te->BaseOfCode <= Hdr.Te->StrippedSize) {
      ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
      return RETURN_UNSUPPORTED;
    }

    //
    // Read last byte of Hdr.Te->SizeOfHeaders from the file.
    //
    Size = 1;
    ReadSize = Size;
    Status = ImageContext->ImageRead (
                             ImageContext->Handle,
                             ImageContext->SizeOfHeaders - 1,
                             &Size,
                             &BufferData
                             );
    if (RETURN_ERROR (Status) || (Size != ReadSize)) {
      ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
      if (Size != ReadSize) {
        Status = RETURN_UNSUPPORTED;
      }
      return Status;
    }

    //
    // TE Image Data Directory Entry size is non-zero, but the Data Directory Virtual Address is zero.
    // This case is not a valid TE image.
    //
    if ((Hdr.Te->DataDirectory[0].Size != 0 && Hdr.Te->DataDirectory[0].VirtualAddress == 0) ||
        (Hdr.Te->DataDirectory[1].Size != 0 && Hdr.Te->DataDirectory[1].VirtualAddress == 0)) {
      ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
      return RETURN_UNSUPPORTED;
    }
  } else if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE)  {
    ImageContext->IsTeImage = FALSE;
    ImageContext->Machine = Hdr.Pe32->FileHeader.Machine;

    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // 1. Check OptionalHeader.NumberOfRvaAndSizes filed.
      //
      if (EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES < Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // 2. Check the FileHeader.SizeOfOptionalHeader field.
      // OptionalHeader.NumberOfRvaAndSizes is not bigger than 16, so
      // OptionalHeader.NumberOfRvaAndSizes * sizeof (EFI_IMAGE_DATA_DIRECTORY) will not overflow.
      //
      HeaderWithoutDataDir = sizeof (EFI_IMAGE_OPTIONAL_HEADER32) - sizeof (EFI_IMAGE_DATA_DIRECTORY) * EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
      if (((UINT32)Hdr.Pe32->FileHeader.SizeOfOptionalHeader - HeaderWithoutDataDir) !=
          Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes * sizeof (EFI_IMAGE_DATA_DIRECTORY)) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      SectionHeaderOffset = ImageContext->PeCoffHeaderOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + Hdr.Pe32->FileHeader.SizeOfOptionalHeader;
      //
      // 3. Check the FileHeader.NumberOfSections field.
      //
      if (Hdr.Pe32->OptionalHeader.SizeOfImage <= SectionHeaderOffset) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      if ((Hdr.Pe32->OptionalHeader.SizeOfImage - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER <= Hdr.Pe32->FileHeader.NumberOfSections) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // 4. Check the OptionalHeader.SizeOfHeaders field.
      //
      if (Hdr.Pe32->OptionalHeader.SizeOfHeaders <= SectionHeaderOffset) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      if (Hdr.Pe32->OptionalHeader.SizeOfHeaders >= Hdr.Pe32->OptionalHeader.SizeOfImage) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      if ((Hdr.Pe32->OptionalHeader.SizeOfHeaders - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER < (UINT32)Hdr.Pe32->FileHeader.NumberOfSections) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // 4.2 Read last byte of Hdr.Pe32.OptionalHeader.SizeOfHeaders from the file.
      //
      Size = 1;
      ReadSize = Size;
      Status = ImageContext->ImageRead (
                               ImageContext->Handle,
                               Hdr.Pe32->OptionalHeader.SizeOfHeaders - 1,
                               &Size,
                               &BufferData
                               );
      if (RETURN_ERROR (Status) || (Size != ReadSize)) {
        ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
        if (Size != ReadSize) {
          Status = RETURN_UNSUPPORTED;
        }
        return Status;
      }

      //
      // Check the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data.
      // Read the last byte to make sure the data is in the image region.
      // The DataDirectory array begin with 1, not 0, so here use < to compare not <=.
      //
      if (EFI_IMAGE_DIRECTORY_ENTRY_SECURITY < Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes) {
        if (Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size != 0) {
          //
          // Check the member data to avoid overflow.
          //
          if ((UINT32) (~0) - Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress <
              Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size) {
            ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
            return RETURN_UNSUPPORTED;
          }

          //
          // Read last byte of section header from file
          //
          Size = 1;
          ReadSize = Size;
          Status = ImageContext->ImageRead (
                                   ImageContext->Handle,
                                   Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress +
                                    Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size - 1,
                                   &Size,
                                   &BufferData
                                   );
          if (RETURN_ERROR (Status) || (Size != ReadSize)) {
            ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
            if (Size != ReadSize) {
              Status = RETURN_UNSUPPORTED;
            }
            return Status;
          }
        }
      }

      //
      // Use PE32 offset
      //
      ImageContext->ImageType         = Hdr.Pe32->OptionalHeader.Subsystem;
      ImageContext->ImageSize         = (UINT64)Hdr.Pe32->OptionalHeader.SizeOfImage;
      ImageContext->SectionAlignment  = Hdr.Pe32->OptionalHeader.SectionAlignment;
      ImageContext->SizeOfHeaders     = Hdr.Pe32->OptionalHeader.SizeOfHeaders;

    } else if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      //
      // 1. Check FileHeader.NumberOfRvaAndSizes filed.
      //
      if (EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES < Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      //
      // 2. Check the FileHeader.SizeOfOptionalHeader field.
      // OptionalHeader.NumberOfRvaAndSizes is not bigger than 16, so
      // OptionalHeader.NumberOfRvaAndSizes * sizeof (EFI_IMAGE_DATA_DIRECTORY) will not overflow.
      //
      HeaderWithoutDataDir = sizeof (EFI_IMAGE_OPTIONAL_HEADER64) - sizeof (EFI_IMAGE_DATA_DIRECTORY) * EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
      if (((UINT32)Hdr.Pe32Plus->FileHeader.SizeOfOptionalHeader - HeaderWithoutDataDir) !=
          Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes * sizeof (EFI_IMAGE_DATA_DIRECTORY)) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      SectionHeaderOffset = ImageContext->PeCoffHeaderOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + Hdr.Pe32Plus->FileHeader.SizeOfOptionalHeader;
      //
      // 3. Check the FileHeader.NumberOfSections field.
      //
      if (Hdr.Pe32Plus->OptionalHeader.SizeOfImage <= SectionHeaderOffset) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      if ((Hdr.Pe32Plus->OptionalHeader.SizeOfImage - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER <= Hdr.Pe32Plus->FileHeader.NumberOfSections) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // 4. Check the OptionalHeader.SizeOfHeaders field.
      //
      if (Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders <= SectionHeaderOffset) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      if (Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders >= Hdr.Pe32Plus->OptionalHeader.SizeOfImage) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }
      if ((Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER < (UINT32)Hdr.Pe32Plus->FileHeader.NumberOfSections) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // 4.2 Read last byte of Hdr.Pe32Plus.OptionalHeader.SizeOfHeaders from the file.
      //
      Size = 1;
      ReadSize = Size;
      Status = ImageContext->ImageRead (
                               ImageContext->Handle,
                               Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - 1,
                               &Size,
                               &BufferData
                               );
      if (RETURN_ERROR (Status) || (Size != ReadSize)) {
        ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
        if (Size != ReadSize) {
          Status = RETURN_UNSUPPORTED;
        }
        return Status;
      }

      //
      // Check the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data.
      // Read the last byte to make sure the data is in the image region.
      // The DataDirectory array begin with 1, not 0, so here use < to compare not <=.
      //
      if (EFI_IMAGE_DIRECTORY_ENTRY_SECURITY < Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes) {
        if (Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size != 0) {
          //
          // Check the member data to avoid overflow.
          //
          if ((UINT32) (~0) - Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress <
              Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size) {
            ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
            return RETURN_UNSUPPORTED;
          }

          //
          // Read last byte of section header from file
          //
          Size = 1;
          ReadSize = Size;
          Status = ImageContext->ImageRead (
                                   ImageContext->Handle,
                                   Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress +
                                    Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size - 1,
                                   &Size,
                                   &BufferData
                                   );
          if (RETURN_ERROR (Status) || (Size != ReadSize)) {
            ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
            if (Size != ReadSize) {
              Status = RETURN_UNSUPPORTED;
            }
            return Status;
          }
        }
      }

      //
      // Use PE32+ offset
      //
      ImageContext->ImageType         = Hdr.Pe32Plus->OptionalHeader.Subsystem;
      ImageContext->ImageSize         = (UINT64) Hdr.Pe32Plus->OptionalHeader.SizeOfImage;
      ImageContext->SectionAlignment  = Hdr.Pe32Plus->OptionalHeader.SectionAlignment;
      ImageContext->SizeOfHeaders     = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
    } else {
      ImageContext->ImageError = IMAGE_ERROR_INVALID_MACHINE_TYPE;
      return RETURN_UNSUPPORTED;
    }
  } else {
    ImageContext->ImageError = IMAGE_ERROR_INVALID_MACHINE_TYPE;
    return RETURN_UNSUPPORTED;
  }

  if (!PeCoffLoaderImageFormatSupported (ImageContext->Machine)) {
    //
    // If the PE/COFF loader does not support the image type return
    // unsupported. This library can support lots of types of images
    // this does not mean the user of this library can call the entry
    // point of the image.
    //
    return RETURN_UNSUPPORTED;
  }

  //
  // Check each section field.
  //
  if (ImageContext->IsTeImage) {
    SectionHeaderOffset = sizeof(EFI_TE_IMAGE_HEADER);
    NumberOfSections    = (UINTN) (Hdr.Te->NumberOfSections);
  } else {
    SectionHeaderOffset = ImageContext->PeCoffHeaderOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + Hdr.Pe32->FileHeader.SizeOfOptionalHeader;
    NumberOfSections    = (UINTN) (Hdr.Pe32->FileHeader.NumberOfSections);
  }

  for (Index = 0; Index < NumberOfSections; Index++) {
    //
    // Read section header from file
    //
    Size = sizeof (EFI_IMAGE_SECTION_HEADER);
    ReadSize = Size;
    Status = ImageContext->ImageRead (
                             ImageContext->Handle,
                             SectionHeaderOffset,
                             &Size,
                             &SectionHeader
                             );
    if (RETURN_ERROR (Status) || (Size != ReadSize)) {
      ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
      if (Size != ReadSize) {
        Status = RETURN_UNSUPPORTED;
      }
      return Status;
    }

    //
    // Adjust some field in Section Header for TE image.
    //
    if (ImageContext->IsTeImage) {
      PeCoffLoaderAdjustOffsetForTeImage (&SectionHeader, (UINT32)Hdr.Te->StrippedSize - sizeof (EFI_TE_IMAGE_HEADER));
    }

    if (SectionHeader.SizeOfRawData > 0) {
      //
      // Section data should bigger than the Pe header.
      //
      if (SectionHeader.VirtualAddress < ImageContext->SizeOfHeaders ||
          SectionHeader.PointerToRawData < ImageContext->SizeOfHeaders) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // Check the member data to avoid overflow.
      //
      if ((UINT32) (~0) - SectionHeader.PointerToRawData < SectionHeader.SizeOfRawData) {
        ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
        return RETURN_UNSUPPORTED;
      }

      //
      // Base on the ImageRead function to check the section data field.
      // Read the last byte to make sure the data is in the image region.
      //
      Size = 1;
      ReadSize = Size;
      Status = ImageContext->ImageRead (
                               ImageContext->Handle,
                               SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData - 1,
                               &Size,
                               &BufferData
                               );
      if (RETURN_ERROR (Status) || (Size != ReadSize)) {
        ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
        if (Size != ReadSize) {
          Status = RETURN_UNSUPPORTED;
        }
        return Status;
      }
    }

    //
    // Check next section.
    //
    SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
  }

  return RETURN_SUCCESS;
}

/**
  Retrieves information about a PE/COFF image.

  Computes the PeCoffHeaderOffset, IsTeImage, ImageType, ImageAddress, ImageSize,
  DestinationAddress, RelocationsStripped, SectionAlignment, SizeOfHeaders, and
  DebugDirectoryEntryRva fields of the ImageContext structure.
  If ImageContext is NULL, then return RETURN_INVALID_PARAMETER.
  If the PE/COFF image accessed through the ImageRead service in the ImageContext
  structure is not a supported PE/COFF image type, then return RETURN_UNSUPPORTED.
  If any errors occur while computing the fields of ImageContext,
  then the error status is returned in the ImageError field of ImageContext.
  If the image is a TE image, then SectionAlignment is set to 0.
  The ImageRead and Handle fields of ImageContext structure must be valid prior
  to invoking this service.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this routine will
  also done many checks in PE image to make sure PE image DosHeader, PeOptionHeader,
  SizeOfHeader, Section Data Region and Security Data Region be in PE image range.

  @param  ImageContext              The pointer to the image context structure that describes the PE/COFF
                                    image that needs to be examined by this function.

  @retval RETURN_SUCCESS            The information on the PE/COFF image was collected.
  @retval RETURN_INVALID_PARAMETER  ImageContext is NULL.
  @retval RETURN_UNSUPPORTED        The PE/COFF image is not supported.

**/
RETURN_STATUS
PeCoffLoaderGetImageInfo (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  uint64_t                              Status;
  EFI_IMAGE_OPTIONAL_HEADER_UNION       HdrData;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION   Hdr;
  EFI_IMAGE_DATA_DIRECTORY              *DebugDirectoryEntry;
  UINTN                                 Size;
  UINTN                                 ReadSize;
  UINTN                                 Index;
  UINTN                                 DebugDirectoryEntryRva;
  UINTN                                 DebugDirectoryEntryFileOffset;
  UINTN                                 SectionHeaderOffset;
  EFI_IMAGE_SECTION_HEADER              SectionHeader;
  EFI_IMAGE_DEBUG_DIRECTORY_ENTRY       DebugEntry;
  UINT32                                NumberOfRvaAndSizes;
  UINT32                                TeStrippedOffset;

  if (ImageContext == NULL) {
    return -1;
  }
  //
  // Assume success
  //
  ImageContext->ImageError  = IMAGE_ERROR_SUCCESS;

  Hdr.Union = &HdrData;
  Status = PeCoffLoaderGetPeHeader (ImageContext, Hdr);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  //
  // Retrieve the base address of the image
  //
  if (!(ImageContext->IsTeImage)) {
    TeStrippedOffset = 0;
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      ImageContext->ImageAddress = Hdr.Pe32->OptionalHeader.ImageBase;
    } else {
      //
      // Use PE32+ offset
      //
      ImageContext->ImageAddress = Hdr.Pe32Plus->OptionalHeader.ImageBase;
    }
  } else {
    TeStrippedOffset = (UINT32)Hdr.Te->StrippedSize - sizeof (EFI_TE_IMAGE_HEADER);
    ImageContext->ImageAddress = (PHYSICAL_ADDRESS)(Hdr.Te->ImageBase + TeStrippedOffset);
  }

  //
  // Initialize the alternate destination address to 0 indicating that it
  // should not be used.
  //
  ImageContext->DestinationAddress = 0;

  //
  // Initialize the debug codeview pointer.
  //
  ImageContext->DebugDirectoryEntryRva = 0;
  ImageContext->CodeView               = NULL;
  ImageContext->PdbPointer             = NULL;

  //
  // Three cases with regards to relocations:
  // - Image has base relocs, RELOCS_STRIPPED==0    => image is relocatable
  // - Image has no base relocs, RELOCS_STRIPPED==1 => Image is not relocatable
  // - Image has no base relocs, RELOCS_STRIPPED==0 => Image is relocatable but
  //   has no base relocs to apply
  // Obviously having base relocations with RELOCS_STRIPPED==1 is invalid.
  //
  // Look at the file header to determine if relocations have been stripped, and
  // save this information in the image context for later use.
  //
  if ((!(ImageContext->IsTeImage)) && ((Hdr.Pe32->FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) != 0)) {
    ImageContext->RelocationsStripped = TRUE;
  } else if ((ImageContext->IsTeImage) && (Hdr.Te->DataDirectory[0].Size == 0) && (Hdr.Te->DataDirectory[0].VirtualAddress == 0)) {
    ImageContext->RelocationsStripped = TRUE;
  } else {
    ImageContext->RelocationsStripped = FALSE;
  }

  if (!(ImageContext->IsTeImage)) {
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      DebugDirectoryEntry = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
    } else {
      //
      // Use PE32+ offset
      //
      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      DebugDirectoryEntry = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
    }

    if (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG) {

      DebugDirectoryEntryRva = DebugDirectoryEntry->VirtualAddress;

      //
      // Determine the file offset of the debug directory...  This means we walk
      // the sections to find which section contains the RVA of the debug
      // directory
      //
      DebugDirectoryEntryFileOffset = 0;

      SectionHeaderOffset = ImageContext->PeCoffHeaderOffset +
                            sizeof (UINT32) +
                            sizeof (EFI_IMAGE_FILE_HEADER) +
                            Hdr.Pe32->FileHeader.SizeOfOptionalHeader;

      for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
        //
        // Read section header from file
        //
        Size = sizeof (EFI_IMAGE_SECTION_HEADER);
        ReadSize = Size;
        Status = ImageContext->ImageRead (
                                 ImageContext->Handle,
                                 SectionHeaderOffset,
                                 &Size,
                                 &SectionHeader
                                 );
        if (RETURN_ERROR (Status) || (Size != ReadSize)) {
          ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
          if (Size != ReadSize) {
            Status = -1;
          }
          return Status;
        }

        if (DebugDirectoryEntryRva >= SectionHeader.VirtualAddress &&
            DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize) {

          DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;
          break;
        }

        SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
      }

      if (DebugDirectoryEntryFileOffset != 0) {
        for (Index = 0; Index < DebugDirectoryEntry->Size; Index += sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)) {
          //
          // Read next debug directory entry
          //
          Size = sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY);
          ReadSize = Size;
          Status = ImageContext->ImageRead (
                                   ImageContext->Handle,
                                   DebugDirectoryEntryFileOffset + Index,
                                   &Size,
                                   &DebugEntry
                                   );
          if (RETURN_ERROR (Status) || (Size != ReadSize)) {
            ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
            if (Size != ReadSize) {
              Status = -1;
            }
            return Status;
          }

          //
          // From PeCoff spec, when DebugEntry.RVA == 0 means this debug info will not load into memory.
          // Here we will always load EFI_IMAGE_DEBUG_TYPE_CODEVIEW type debug info. so need adjust the
          // ImageContext->ImageSize when DebugEntry.RVA == 0.
          //
          if (DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW) {
            ImageContext->DebugDirectoryEntryRva = (UINT32) (DebugDirectoryEntryRva + Index);
            if (DebugEntry.RVA == 0 && DebugEntry.FileOffset != 0) {
              ImageContext->ImageSize += DebugEntry.SizeOfData;
            }

            return 0;
          }
        }
      }
    }
  } else {

    DebugDirectoryEntry             = &Hdr.Te->DataDirectory[1];
    DebugDirectoryEntryRva          = DebugDirectoryEntry->VirtualAddress;
    SectionHeaderOffset             = (UINTN)(sizeof (EFI_TE_IMAGE_HEADER));

    DebugDirectoryEntryFileOffset   = 0;

    for (Index = 0; Index < Hdr.Te->NumberOfSections;) {
      //
      // Read section header from file
      //
      Size   = sizeof (EFI_IMAGE_SECTION_HEADER);
      ReadSize = Size;
      Status = ImageContext->ImageRead (
                               ImageContext->Handle,
                               SectionHeaderOffset,
                               &Size,
                               &SectionHeader
                               );
      if (RETURN_ERROR (Status) || (Size != ReadSize)) {
        ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
        if (Size != ReadSize) {
          Status = -1;
        }
        return Status;
      }

      if (DebugDirectoryEntryRva >= SectionHeader.VirtualAddress &&
          DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize) {
        DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva -
                                        SectionHeader.VirtualAddress +
                                        SectionHeader.PointerToRawData -
                                        TeStrippedOffset;

        //
        // File offset of the debug directory was found, if this is not the last
        // section, then skip to the last section for calculating the image size.
        //
        if (Index < (UINTN) Hdr.Te->NumberOfSections - 1) {
          SectionHeaderOffset += (Hdr.Te->NumberOfSections - 1 - Index) * sizeof (EFI_IMAGE_SECTION_HEADER);
          Index = Hdr.Te->NumberOfSections - 1;
          continue;
        }
      }

      //
      // In Te image header there is not a field to describe the ImageSize.
      // Actually, the ImageSize equals the RVA plus the VirtualSize of
      // the last section mapped into memory (Must be rounded up to
      // a multiple of Section Alignment). Per the PE/COFF specification, the
      // section headers in the Section Table must appear in order of the RVA
      // values for the corresponding sections. So the ImageSize can be determined
      // by the RVA and the VirtualSize of the last section header in the
      // Section Table.
      //
      if ((++Index) == (UINTN)Hdr.Te->NumberOfSections) {
        ImageContext->ImageSize = (SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize) - TeStrippedOffset;
      }

      SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
    }

    if (DebugDirectoryEntryFileOffset != 0) {
      for (Index = 0; Index < DebugDirectoryEntry->Size; Index += sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)) {
        //
        // Read next debug directory entry
        //
        Size = sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY);
        ReadSize = Size;
        Status = ImageContext->ImageRead (
                                 ImageContext->Handle,
                                 DebugDirectoryEntryFileOffset + Index,
                                 &Size,
                                 &DebugEntry
                                 );
        if (RETURN_ERROR (Status) || (Size != ReadSize)) {
          ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
          if (Size != ReadSize) {
            Status = -1;
          }
          return Status;
        }

        if (DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW) {
          ImageContext->DebugDirectoryEntryRva = (UINT32) (DebugDirectoryEntryRva + Index);
          return 0;
        }
      }
    }
  }

  return 0;
}

int
LoadPeImage (
  uint8_t **buf,
  uint64_t *size,
  const char *filename)
{
  struct stat st;
  int ret = stat(filename, &st);
  if (ret) {
    printf("Failed to get filesize of %s\n", filename);
    return -1;
  }
  uint64_t file_size = st.st_size;

  *buf = (uint8_t *)malloc(sizeof(uint8_t) * file_size);
  if (!*buf) {
    printf("Failed to allocate memory\n");
    return -1;
  }
  FILE *f = fopen(filename, "rb");
  if (!f) {
    printf("Failed to open %s\n", filename);
    free(buf);
    return -1;
  }
  size_t data_read = fread(*buf, 1, file_size, f);
  fclose(f);
  if (data_read != (size_t)file_size) {
    printf("Failed to read file. Only read: %ld of %ld\n", data_read, file_size);
    free(buf);
    return -1;
  }
  DEBUG("Read kernel pe/coff file %s with size %ld\n", filename, data_read);

  *size = file_size;

  return 0;
}

#define  SIZE_4KB    0x00001000

#define EFI_PAGE_SIZE             SIZE_4KB

#define EFI_SIZE_TO_PAGES(Size)  (((Size) >> EFI_PAGE_SHIFT) + (((Size) & EFI_PAGE_MASK) ? 1 : 0))

uint64_t
MeasurePeImageSha256(
    uint8_t *hash,
    const uint8_t *buf,
    uint64_t buf_size)
{
    const EVP_MD *md = EVP_sha256();
    return MeasurePeImage(md, hash, buf, buf_size);
}

uint64_t
MeasurePeImageSha384(
    uint8_t *hash,
    const uint8_t *buf,
    uint64_t buf_size)
{
    const EVP_MD *md = EVP_sha384();
    return MeasurePeImage(md, hash, buf, buf_size);
}

EFI_STATUS
MeasurePeImage (
  const EVP_MD *md,
  uint8_t *hash,
  const uint8_t *buf,
  const UINTN buf_size)
{
  EFI_STATUS                           Status;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_SECTION_HEADER             *Section;
  UINT8                                *HashBase;
  UINTN                                HashSize;
  UINTN                                SumOfBytesHashed;
  EFI_IMAGE_SECTION_HEADER             *SectionHeader;
  UINTN                                Index;
  UINTN                                Pos;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT32                               NumberOfRvaAndSizes;
  UINT32                               CertSize;
  PE_COFF_LOADER_IMAGE_CONTEXT         ImageContext;
  EFI_PHYSICAL_ADDRESS                 ImageAddress;

  Status        = EFI_UNSUPPORTED;
  SectionHeader = NULL;
  ImageAddress = (EFI_PHYSICAL_ADDRESS) buf;
  EVP_MD_CTX *ctx = NULL;

  DEBUG("Measuring PE Image..\n");

  //
  // Check PE/COFF image
  //
  memset (&ImageContext, 0x0, sizeof (ImageContext));
  ImageContext.Handle    = (VOID *) (UINTN) ImageAddress;
  mTcg2DxeImageSize      = buf_size;
  ImageContext.ImageRead = (PE_COFF_LOADER_READ_FILE) Tcg2DxeImageRead;

  //
  // Get information about the image being loaded
  //
  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    //
    // The information can't be got from the invalid PeImage
    //
    DEBUG("\tTcg2Dxe: PeImage invalid. Cannot retrieve image information.\n");
    goto Finish;
  }

  DEBUG("\tImageAddress: 0x%llx\n", ImageContext.ImageAddress);
  DEBUG("\tImageType: 0x%x\n", ImageContext.ImageType);
  DEBUG("\tPeCoffHeaderOffset: 0x%x\n", ImageContext.PeCoffHeaderOffset);
  DEBUG("\tSizeOfHeaders: 0x%llx\n", ImageContext.SizeOfHeaders);

  DosHdr = (EFI_IMAGE_DOS_HEADER *) (UINTN) ImageAddress;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  DEBUG("\tPeCoffHeaderOffset = %d\n", PeCoffHeaderOffset);

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *) (UINTN) ImageAddress + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    Status = EFI_UNSUPPORTED;
    goto Finish;
  }

  //
  // PE/COFF Image Measurement
  //
  //    NOTE: The following codes/steps are based upon the authenticode image hashing in
  //      PE/COFF Specification 8.0 Appendix A.
  //
  //

  // 2.  Initialize a SHA hash context.

  ctx = EVP_MD_CTX_new();
  if (!ctx) {
      goto Finish;
  }

  if (!EVP_DigestInit_ex(ctx, md, NULL)) {
      goto Finish;
  }

  //
  // Measuring PE/COFF Image Header;
  // But CheckSum field and SECURITY data directory (certificate) are excluded
  //

  //
  // 3.  Calculate the distance from the base of the image header to the image checksum address.
  // 4.  Hash the image header from its base to beginning of the image checksum.
  //
  HashBase = (UINT8 *) (UINTN) ImageAddress;
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset
    //
    NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    HashSize = (UINTN) (&Hdr.Pe32->OptionalHeader.CheckSum) - (UINTN) HashBase;

    DEBUG("\tHeader Magic: %d\n", Hdr.Pe32->OptionalHeader.Magic);
    DEBUG("\tNumberOfRvaAndSizes: %d\n", NumberOfRvaAndSizes);
    DEBUG("\tHashSize: %lld\n", HashSize);

  } else {
    //
    // Use PE32+ offset
    //
    NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    HashSize = (UINTN) (&Hdr.Pe32Plus->OptionalHeader.CheckSum) - (UINTN) HashBase;

    DEBUG("\tHeader Magic +: %d\n", Hdr.Pe32->OptionalHeader.Magic);
    DEBUG("\tNumberOfRvaAndSizes: %d\n", NumberOfRvaAndSizes);
    DEBUG("\tHashSize: %lld\n", HashSize);
  }

  Status = EVP_DigestUpdate(ctx, HashBase, HashSize);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

  //
  // 5.  Skip over the image checksum (it occupies a single ULONG).
  //
  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    //
    // 6.  Since there is no Cert Directory in optional header, hash everything
    //     from the end of the checksum to the end of image header.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *) &Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *) &Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    }

    if (HashSize != 0) {
      Status = EVP_DigestUpdate(ctx, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    }
  } else {
    //
    // 7.  Hash everything from the end of the checksum to the start of the Cert Directory.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN) (&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN) HashBase;
    } else {
      //
      // Use PE32+ offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN) (&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN) HashBase;
    }

    if (HashSize != 0) {
      Status = EVP_DigestUpdate(ctx, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    }

    //
    // 8.  Skip over the Cert Directory. (It is sizeof(IMAGE_DATA_DIRECTORY) bytes.)
    // 9.  Hash everything from the end of the Cert Directory to the end of image header.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    } else {
      //
      // Use PE32+ offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    }

    if (HashSize != 0) {
      Status = EVP_DigestUpdate(ctx, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    }
  }

  //
  // 10. Set the SUM_OF_BYTES_HASHED to the size of the header
  //
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset
    //
    SumOfBytesHashed = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
  } else {
    //
    // Use PE32+ offset
    //
    SumOfBytesHashed = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
  }

  //
  // 11. Build a temporary table of pointers to all the IMAGE_SECTION_HEADER
  //     structures in the image. The 'NumberOfSections' field of the image
  //     header indicates how big the table should be. Do not include any
  //     IMAGE_SECTION_HEADERs in the table whose 'SizeOfRawData' field is zero.
  //
  SectionHeader = (EFI_IMAGE_SECTION_HEADER *) calloc (Hdr.Pe32->FileHeader.NumberOfSections, sizeof (EFI_IMAGE_SECTION_HEADER));
  if (SectionHeader == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Finish;
  }

  //
  // 12.  Using the 'PointerToRawData' in the referenced section headers as
  //      a key, arrange the elements in the table in ascending order. In other
  //      words, sort the section headers according to the disk-file offset of
  //      the section.
  //
  Section = (EFI_IMAGE_SECTION_HEADER *) (
               (UINT8 *) (UINTN) ImageAddress +
               PeCoffHeaderOffset +
               sizeof(UINT32) +
               sizeof(EFI_IMAGE_FILE_HEADER) +
               Hdr.Pe32->FileHeader.SizeOfOptionalHeader
               );
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Pos = Index;
    while ((Pos > 0) && (Section->PointerToRawData < SectionHeader[Pos - 1].PointerToRawData)) {
      memcpy (&SectionHeader[Pos], &SectionHeader[Pos - 1], sizeof(EFI_IMAGE_SECTION_HEADER));
      Pos--;
    }
    memcpy (&SectionHeader[Pos], Section, sizeof(EFI_IMAGE_SECTION_HEADER));
    Section += 1;
  }

  //
  // 13.  Walk through the sorted table, bring the corresponding section
  //      into memory, and hash the entire section (using the 'SizeOfRawData'
  //      field in the section header to determine the amount of data to hash).
  // 14.  Add the section's 'SizeOfRawData' to SUM_OF_BYTES_HASHED .
  // 15.  Repeat steps 13 and 14 for all the sections in the sorted table.
  //
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Section  = (EFI_IMAGE_SECTION_HEADER *) &SectionHeader[Index];
    if (Section->SizeOfRawData == 0) {
      continue;
    }
    HashBase = (UINT8 *) (UINTN) ImageAddress + Section->PointerToRawData;
    HashSize = (UINTN) Section->SizeOfRawData;

    Status = EVP_DigestUpdate(ctx, HashBase, HashSize);
    if (EFI_ERROR (Status)) {
      goto Finish;
    }

    SumOfBytesHashed += HashSize;
    DEBUG("\t\tSum: %lld, SizeOfRawData: %lld, HashBase: %p\n", SumOfBytesHashed, (UINTN) Section->SizeOfRawData, HashBase);
  }

  //
  // 16.  If the file size is greater than SUM_OF_BYTES_HASHED, there is extra
  //      data in the file that needs to be added to the hash. This data begins
  //      at file offset SUM_OF_BYTES_HASHED and its length is:
  //             FileSize  -  (CertDirectory->Size)
  //
  if (buf_size > SumOfBytesHashed) {
    HashBase = (UINT8 *) (UINTN) ImageAddress + SumOfBytesHashed;

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      CertSize = 0;
    } else {
      if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        //
        // Use PE32 offset.
        //
        CertSize = Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      } else {
        //
        // Use PE32+ offset.
        //
        CertSize = Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      }
    }

    if (buf_size > CertSize + SumOfBytesHashed) {
      HashSize = (UINTN) (buf_size - CertSize - SumOfBytesHashed);

      Status = EVP_DigestUpdate(ctx, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    } else if (buf_size < CertSize + SumOfBytesHashed) {
      Status = EFI_UNSUPPORTED;
      goto Finish;
    }
  }

  DEBUG("\tSumOfBytesHashed: %lld\n", SumOfBytesHashed);
  DEBUG("\tHashBase = %p\n", HashBase);
  DEBUG("\tImageAddress = %llx\n", ImageAddress);
  DEBUG("\tHashBase - ImageBuf = %llx\n", (UINTN) HashBase - ImageAddress);

  //
  // 17.  Finalize the SHA hash.
  //
  EVP_DigestFinal_ex(ctx, hash, NULL);

  Status = EFI_SUCCESS;

Finish:
  if (SectionHeader != NULL) {
    free (SectionHeader);
  }
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }

  DEBUG("Finished. Return Status %lld\n", Status);

  return Status;
}
