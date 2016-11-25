#include <stdint.h>
#include "coff.h"
#include "dos.h"

#ifndef PE_STRUCT_H
#define PE_STRUCT_H

typedef struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress; //Offset from image base
    uint32_t Size; //Size of data
} __attribute__((packed)) IMAGE_DATA_DIRECTORY;

typedef struct Header_Data_Directory {
    IMAGE_DATA_DIRECTORY exportTable; //.edata
    IMAGE_DATA_DIRECTORY importTable; //.idata
    IMAGE_DATA_DIRECTORY resourceTable; //.rsrc
    IMAGE_DATA_DIRECTORY exceptionTable; //.pdata
    IMAGE_DATA_DIRECTORY certificateTable;
    IMAGE_DATA_DIRECTORY baseRelocationTable; //.reloc
    IMAGE_DATA_DIRECTORY debug; //.debug
    IMAGE_DATA_DIRECTORY architecture;
    IMAGE_DATA_DIRECTORY globalPtr;
    IMAGE_DATA_DIRECTORY TLSTable; //.tls
    IMAGE_DATA_DIRECTORY loadConfigTable;
    IMAGE_DATA_DIRECTORY boundImport;
    IMAGE_DATA_DIRECTORY IAT;
    IMAGE_DATA_DIRECTORY delayImportDescriptor;
    IMAGE_DATA_DIRECTORY CLRRuntimeHeader; //.cormeta
    uint64_t reserved;
} __attribute__((packed)) Header_Data_Directory;

typedef struct SECTION_TABLE {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} __attribute__((packed)) SECTION_TABLE;

typedef struct SectionTableNode {
    SECTION_TABLE Section_Header;
    struct SectionTableNode *next;
} __attribute__((packed)) SectionTableNode;

//SECTION_TABLE.Characteristics Flags
static uint32_t IMAGE_SCN_TYPE_NO_PAD          = 0x00000008;
static uint32_t IMAGE_SCN_CNT_CODE             = 0x00000020;
static uint32_t IMAGE_SCN_INITIALIZED_DATA     = 0x00000040;
static uint32_t IMAGE_SCN_UNINITIALIZED_DATA   = 0x00000080;
static uint32_t IMAGE_SCN_LNK_OTHER            = 0x00000100;
static uint32_t IMAGE_SCN_LNK_INFO             = 0x00000200;
static uint32_t IMAGE_SCN_LNK_REMOVE           = 0x00000800;
static uint32_t IMAGE_SCN_LNK_COMDAT           = 0x00001000;
static uint32_t IMAGE_SCN_GPREL                = 0x00008000;
static uint32_t IMAGE_SCN_MEM_PURGEABLE        = 0x00020000;
static uint32_t IMAGE_SCN_MEM_16BIT            = 0x00020000;
static uint32_t IMAGE_SCN_MEM_LOCKED           = 0x00040000;
static uint32_t IMAGE_SCN_PRELOAD              = 0x00080000;
static uint32_t IMAGE_SCN_ALIGN_1BYTES         = 0x00100000;
static uint32_t IMAGE_SCN_ALIGN_2BYTES         = 0x00200000;
static uint32_t IMAGE_SCN_ALIGN_4BYTES         = 0x00300000;
static uint32_t IMAGE_SCN_ALIGN_8BYTES         = 0x00400000;
static uint32_t IMAGE_SCN_ALIGN_16BYTES        = 0x00500000;
static uint32_t IMAGE_SCN_ALIGN_32BYTES        = 0x00600000;
static uint32_t IMAGE_SCN_ALIGN_64BYTES        = 0x00700000;
static uint32_t IMAGE_SCN_ALIGN_128BYTES       = 0x00800000;
static uint32_t IMAGE_SCN_ALIGN_256BYTES       = 0x00900000;
static uint32_t IMAGE_SCN_ALIGN_512BYTES       = 0x00A00000;
static uint32_t IMAGE_SCN_ALIGN_1024BYTES      = 0x00B00000;
static uint32_t IMAGE_SCN_ALIGN_2048BYTES      = 0x00C00000;
static uint32_t IMAGE_SCN_ALIGN_4096BYTES      = 0x00D00000;
static uint32_t IMAGE_SCN_ALIGN_8192BYTES      = 0x00E00000;
static uint32_t IMAGE_SCN_LNK_NRELOC_OVFL      = 0x01000000;
static uint32_t IMAGE_SCN_MEM_DISCARDABLE      = 0x02000000;
static uint32_t IMAGE_SCN_MEM_NOT_CACHED       = 0x04000000;
static uint32_t IMAGE_SCN_MEM_NOT_PAGED        = 0x08000000;
static uint32_t IMAGE_SCN_MEM_NOT_SHARED       = 0x10000000;
static uint32_t IMAGE_SCN_MEM_EXECUTE          = 0x20000000;
static uint32_t IMAGE_SCN_MEM_READ             = 0x40000000;
static uint32_t IMAGE_SCN_MEM_WRITE            = 0x80000000;
//End

typedef struct PE32_Header {
    uint16_t magic;
    uint8_t  majorLinkerVersion;
    uint8_t  minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint32_t baseOfData;
    uint32_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    Header_Data_Directory dataDirectories;
} __attribute__((packed)) PE32_Header;

typedef struct PE32PLUS_Header {
    uint16_t magic;
    uint8_t  majorLinkerVersion;
    uint8_t  minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint64_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint64_t sizeOfStackReserve;
    uint64_t sizeOfStackCommit;
    uint64_t sizeOfHeapReserve;
    uint64_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    Header_Data_Directory dataDirectories;
} __attribute__((packed)) PE32PLUS_Header;

typedef struct PE_Header {
    char signature[4];
    COFF_Header PE_COFF_Header;
} __attribute__((packed)) PE_Header;

//Windows Subsystem values
static uint16_t IMAGE_SUBSYSTEM_UNKNOWN                    = 0;
static uint16_t IMAGE_SUBSYSTEM_NATIVE                     = 1;
static uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI                = 2;
static uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI                = 3;
static uint16_t IMAGE_SUBSYSTEM_POSIX_CUI                  = 7;
static uint16_t IMAGE_SUBSYSTEM_WINDOWS_CE_GUI             = 9;
static uint16_t IMAGE_SUBSYSTEM_EFI_APPLICATION            = 10;
static uint16_t IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    = 11;
static uint16_t IMAGE_SUBSYSTEM_RUNTIME_DRIVER             = 12;
static uint16_t IMAGE_SUBSYSTEM_ROM                        = 13;
static uint16_t IMAGE_SUBSYSTEM_XBOX                       = 14;
//End Windows Subsystem values

//DLL Characteristics
//Characterstics 0x0001, 0x0002, 0x0004, 0x0008 are reserved and must be zero.
static uint16_t IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020;
static uint16_t IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040;
static uint16_t IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080;
static uint16_t IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100;
static uint16_t IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200;
static uint16_t IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400;
static uint16_t IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800;
static uint16_t IMAGE_DLLCHARACTERISTICS_APPCONTAINER          = 0x1000;
static uint16_t IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000;
static uint16_t IMAGE_DLLCHARACTERISTICS_GUARD_CF              = 0x4000;
static uint16_t IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000;
//End DLL Characteristics

typedef struct Export_Directory_Table {
    uint32_t ExportFlags;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t NameRVA;
    uint32_t OrdinalBase;
    uint32_t AddressTableEntries;
    uint32_t NumberofNamePointers;
    uint32_t ExportAddressTableRVA;
    uint32_t NamePointerRVA;
    uint32_t OrdinalTableRVA;
} __attribute__((packed)) Export_Directory_Table;

#endif
