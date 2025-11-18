/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include "stdbool.h"
#include <openssl/evp.h>
#include "UefiBaseType.h"

// https://github.com/torvalds/linux/blob/master/Documentation/x86/boot.rst
typedef enum __attribute__ ((__packed__))
{
  LILO = 0x00,
  LOADLIN = 0x10,
  BOOTSECT_LOADER = 0x20,
  SYSLINUX  = 0x30,
  PXE = 0x40,
  ELILO = 0x50,
  GRUB = 0x70,
  UBOOT = 0x80,
  XEN = 0x90,
  GUJIN = 0xA0,
  QEMU = 0xB0,
  UCBOOTLOADER = 0xC0,
  KEXEC = 0xD0,
  EXTENDED = 0xE0,
  SPECIAL = 0xF0,
  MINIMAL_LINUX_BOOTLOADER = 0x11,
  OVMF = 0x12,
  UNDEFINED = 0xFF
} type_of_loader_t;

// https://github.com/torvalds/linux/blob/master/Documentation/x86/boot.rst
typedef struct __attribute__((packed))
{
  uint8_t not_implemented[0x210];
  uint8_t type_of_loader;
  uint8_t loadflags;
  uint16_t setup_move_size;
  uint32_t code32_start;
  uint32_t ramdisk_image;
  uint32_t ramdisk_size;
  uint32_t bootsect_kludge;
  uint16_t heap_end_ptr;
  uint8_t ext_loader_ver;
  uint8_t ext_loader_type;
  uint32_t cmd_line_ptr;
  uint32_t ramdisk_max;
} kernel_setup_hdr_t;

void
SetDebug();

int
LoadPeImage (uint8_t **buf, uint64_t *size, const char *filename);

EFI_STATUS
MeasurePeImage (const EVP_MD *md, uint8_t *hash, const uint8_t *buf, const UINTN buf_size);

uint64_t
MeasurePeImageSha256(uint8_t *hash, const uint8_t *buf, const uint64_t buf_size);

uint64_t
MeasurePeImageSha384(uint8_t *hash, const uint8_t *buf, const uint64_t buf_size);