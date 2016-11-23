#ifndef _COFF_H_
#define _COFF_H_

typedef struct _COFF_Header {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
} __attribute__((packed)) COFF_Header;

//Machine Types
uint16_t IMAGE_FILE_MACHINE_UNKNOWN     = 0x0000;
uint16_t IMAGE_FILE_MACHINE_AM33        = 0x01D3;
uint16_t IMAGE_FILE_MACHINE_AMD64       = 0x8664;
uint16_t IMAGE_FILE_MACHINE_ARM         = 0x01C0;
uint16_t IMAGE_FILE_MACHINE_ARM64       = 0xAA64;
uint16_t IMAGE_FILE_MACHINE_ARMNT       = 0x01C4;
uint16_t IMAGE_FILE_MACHINE_EBC         = 0x0EBC;
uint16_t IMAGE_FILE_MACHINE_I386        = 0x014C;
uint16_t IMAGE_FILE_MACHINE_IA64        = 0x0200;
uint16_t IMAGE_FILE_MACHINE_M32R        = 0x9041;
uint16_t IMAGE_FILE_MACHINE_MIPS16      = 0x0266;
uint16_t IMAGE_FILE_MACHINE_MIPSFPU     = 0x0366;
uint16_t IMAGE_FILE_MACHINE_MIPSFPU16   = 0x0466;
uint16_t IMAGE_FILE_MACHINE_POWERPC     = 0x01F0;
uint16_t IMAGE_FILE_MACHINE_POWERPCFP   = 0x01F1;
uint16_t IMAGE_FILE_MACHINE_R4000       = 0x0166;
uint16_t IMAGE_FILE_MACHINE_RISCV32     = 0x5032;
uint16_t IMAGE_FILE_MACHINE_RISCV64     = 0x5064;
uint16_t IMAGE_FILE_MACHINE_RISCV128    = 0x5128;
uint16_t IMAGE_FILE_MACHINE_SH3         = 0x01A2;
uint16_t IMAGE_FILE_MACHINE_SH3DSP      = 0x01A3;
uint16_t IMAGE_FILE_MACHINE_SH4         = 0x01A6;
uint16_t IMAGE_FILE_MACHINE_SH5         = 0x01A8;
uint16_t IMAGE_FILE_MACHINE_THUMB       = 0x01C2;
uint16_t IMAGE_FILE_MACHINE_WCEMIPSV2   = 0x0169;
//End Machine Types

//Characteristics
uint16_t IMAGE_FILE_RELOCS_STRIPPER         = 0x0001;
uint16_t IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002;
uint16_t IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004;
uint16_t IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008;
uint16_t IMAGE_FILE_AGGRESSIVE_WS_TRIM      = 0x0010;
uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020;
//                                            0x0040 Reserved
uint16_t IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080;
uint16_t IMAGE_FILE_32BIT_MACHINE           = 0x0100;
uint16_t IMAGE_FILE_DEBUG_STRIPPED          = 0x0200;
uint16_t IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
uint16_t IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800;
uint16_t IMAGE_FILE_SYSTEM                  = 0x1000;
uint16_t IMAGE_FILE_DLL                     = 0x2000;
uint16_t IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000;
uint16_t IMAGE_FILE_FILE_BYTES_REVERSED_HI  = 0x8000;
//End Characteristics

#endif
