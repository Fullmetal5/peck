#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "includes/dos.h"
#include "includes/pe.h"

typedef struct _SectionTableNode {
    SECTION_TABLE Section_Header;
    struct SectionTableNode *next;
} __attribute__((packed)) SectionTableNode;

int check_flag_8(uint8_t flags, uint8_t flagToCheck){
    return (flags & flagToCheck) == flagToCheck;
}

int check_flag_16(uint16_t flags, uint16_t flagToCheck){
    return (flags & flagToCheck) == flagToCheck;
}

int check_flag_32(uint32_t flags, uint32_t flagToCheck){
    return (flags & flagToCheck) == flagToCheck;
}

int check_flag_64(uint64_t flags, uint64_t flagToCheck){
    return (flags & flagToCheck) == flagToCheck;
}

//The documentation only uses RVAs relative to the Base Image address so we don't account for it here.
//This should not be used to resolve real memory address of the program!
uint64_t resolveRVA(SectionTableNode *root, uint64_t address){
    SectionTableNode *current = root;
    while (current != 0){
        if (current->Section_Header.VirtualAddress < address < current->Section_Header.VirtualSize){
            return address - current->Section_Header.VirtualAddress + current->Section_Header.PointerToRawData;
        }
        current = current->next;
    }
    printf("WARNING: Couldn't resolve RVA 0x%.16X\n", address);
    return 0;
}

//Use this for resolving real memory addresses!
uint64_t resolveRealMemoryAddress(PE32_Header *extractedPE32_Header, SectionTableNode *root, uint64_t address){
    address = address - extractedPE32_Header->imageBase;
    SectionTableNode *current = root;
    while (current != 0){
        if (current->Section_Header.VirtualAddress < address < current->Section_Header.VirtualSize){
            return address - current->Section_Header.VirtualAddress + current->Section_Header.PointerToRawData;
        }
        current = current->next;
    }
    printf("WARNING: Couldn't resolve real memory address 0x%.16X\n", address);
    return 0;
}

uint64_t resolveEntryPoint(PE32_Header *extractedPE32_Header, SectionTableNode *root){
    return resolveRVA(root, extractedPE32_Header->addressOfEntryPoint);
}

DOS_Header* getDOS_Header(FILE *PE_FILE){
    DOS_Header *extractedDOS_Header = malloc(sizeof(DOS_Header));
    fseek(PE_FILE, 0, SEEK_SET);
    fread(extractedDOS_Header, 1, sizeof(DOS_Header), PE_FILE);
    return extractedDOS_Header;
}

PE_Header* getPE_Header(FILE *PE_FILE, DOS_Header *extractedDOS_Header){
    PE_Header *extractedPE_Header = malloc(sizeof(PE_Header));
    fseek(PE_FILE, extractedDOS_Header->e_lfanew, SEEK_SET);
    fread(extractedPE_Header, 1, sizeof(PE_Header), PE_FILE);
    return extractedPE_Header;
}

PE32_Header* getPE32_Header(FILE *PE_FILE, DOS_Header *extractedDOS_Header){
    PE32_Header *extractedPE32_Header = malloc(sizeof(PE32_Header));
    fseek(PE_FILE, (extractedDOS_Header->e_lfanew + sizeof(PE_Header)), SEEK_SET);
    fread(extractedPE32_Header, 1, sizeof(PE32_Header), PE_FILE);
    return extractedPE32_Header;
}

Export_Directory_Table* getExportDirectoryTable(FILE *PE_FILE, SectionTableNode *root, PE32_Header *extractedPE32_Header){
    Export_Directory_Table *extractedExportDirectoryTable = malloc(sizeof(Export_Directory_Table));
    fseek(PE_FILE, resolveRVA(root, extractedPE32_Header->dataDirectories.exportTable.VirtualAddress), SEEK_SET);
    fread(extractedExportDirectoryTable, 1, sizeof(Export_Directory_Table), PE_FILE);
    return extractedExportDirectoryTable;
}

SectionTableNode* constructSectionTableLinkedList(FILE *PE_FILE, DOS_Header *extractedDOS_Header, PE_Header *extractedPE_Header){
    if (extractedPE_Header->PE_COFF_Header.numberOfSections == 0){
        return NULL;
    }
    SectionTableNode *root = malloc(sizeof(SectionTableNode));
    SectionTableNode *current = root;
    root->next = 0;
    fseek(PE_FILE, (extractedDOS_Header->e_lfanew + sizeof(PE_Header) + extractedPE_Header->PE_COFF_Header.sizeOfOptionalHeader), SEEK_SET);
    fread(&root->Section_Header, 1, sizeof(SECTION_TABLE), PE_FILE);
    if (extractedPE_Header->PE_COFF_Header.numberOfSections == 1){
        return root;
    }
    for (int i = 1; i <= extractedPE_Header->PE_COFF_Header.numberOfSections; i++){
        current->next = malloc(sizeof(SectionTableNode));
        current = current->next;
        current->next = 0;
        fread(&current->Section_Header, 1, sizeof(SECTION_TABLE), PE_FILE);
    }
    return root;
}

void freeSectionTableLinkedList(SectionTableNode *root){
    SectionTableNode *previous = root;
    SectionTableNode *current = root;
    while (current != 0){
        current = current->next;
        free(previous);
        previous = current;
    }
}

//WARNING Make sure the string you pass is UTF-8!
SectionTableNode* findSectionTable(SectionTableNode *root, char name[8]){
    SectionTableNode *current = root;
    while (current != 0){
        if (strncmp(current->Section_Header.Name, name, 8) == 0){
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void dumpSections(SectionTableNode *root){
    if (root == NULL)
        return;
    SectionTableNode *current = root;
    //TODO Deal with Grouped Sections (see page 19)
    while (current->next != 0){
        printf("Name: %c%c%c%c%c%c%c%c\n", current->Section_Header.Name[0], current->Section_Header.Name[1], current->Section_Header.Name[2], current->Section_Header.Name[3], current->Section_Header.Name[4], current->Section_Header.Name[5], current->Section_Header.Name[6], current->Section_Header.Name[7]);
        printf("Virtual Size: 0x%.8X\n", current->Section_Header.VirtualSize);
        printf("Virtual Address: 0x%.8X\n", current->Section_Header.VirtualAddress);
        printf("Size of Raw Data: 0x%.8X\n", current->Section_Header.SizeOfRawData);
        printf("Pointer To Raw Data: 0x%.8X\n", current->Section_Header.PointerToRawData);
        printf("Pointer To Relocations: 0x%.8X\n", current->Section_Header.PointerToRelocations);
        printf("Pointer To Line Numbers: 0x%.8X\n", current->Section_Header.PointerToLinenumbers);
        printf("Number of Relocations: 0x%.4X\n", current->Section_Header.NumberOfRelocations);
        printf("Number of Line Numbers: 0x%.4X\n", current->Section_Header.NumberOfLinenumbers);
        printf("Characteristics: 0x%.8X\n", current->Section_Header.Characteristics);
        current = current->next;
    }
}

int main(int argc, char *argv[]){
    if (argc != 2){
        return 0;
    }
    printf("Analysing %s\n", argv[1]);
    FILE *pe = fopen(argv[1], "r");
    DOS_Header *myDOSHeader = getDOS_Header(pe);

    /*printf("----------DOS HEADER----------\n");
    printf("Signature: %c%c\n", myDOSHeader->signature[0], myDOSHeader->signature[1]);
    printf("Bytes used on last page: 0x%.4X\n", myDOSHeader->lastPage);
    printf("Pages: 0x%.4X\n", myDOSHeader->pages);
    printf("Number of relocation items: 0x%.4X\n", myDOSHeader->relocationItems);
    printf("Header size: 0x%.4X\n", myDOSHeader->headerSize);
    printf("Minimum Allocation: 0x%.4X\n", myDOSHeader->minAlloc);
    printf("Maximum Allocation: 0x%.4X\n", myDOSHeader->maxAlloc);
    printf("SS: 0x%.4X\n", myDOSHeader->SS);
    printf("SP: 0x%.4X\n", myDOSHeader->SP);
    printf("Checksum: 0x%.4X\n", myDOSHeader->checksum);
    printf("IP: 0x%.4X\n", myDOSHeader->IP);
    printf("CS: 0x%.4X\n", myDOSHeader->CS);
    printf("Relocation Table: 0x%.4X\n", myDOSHeader->relocationTable);
    printf("Overlay: 0x%.4X\n", myDOSHeader->overlay);
    printf("e_lfanew: 0x%.8X\n", myDOSHeader->e_lfanew);*/
    
    PE_Header *myPEHeader = getPE_Header(pe, myDOSHeader);

    /*printf("----------PE HEADER----------\n");
    printf("Signature: %c%c%c%c\n", myPEHeader->signature[0], myPEHeader->signature[1], myPEHeader->signature[2], myPEHeader->signature[3]);
    printf("Machine: 0x%.4X\n", myPEHeader->PE_COFF_Header.machine);
    printf("Number of Sections: 0x%.4X\n", myPEHeader->PE_COFF_Header.numberOfSections);
    printf("Time Date Stamp: 0x%.8X\n", myPEHeader->PE_COFF_Header.timeDateStamp);
    printf("Pointer to Symbol Table: 0x%.8X\n", myPEHeader->PE_COFF_Header.pointerToSymbolTable);
    printf("Number of Symbols: 0x%.8X\n", myPEHeader->PE_COFF_Header.numberOfSymbols);
    printf("Size of Optional Header: 0x%.4X\n", myPEHeader->PE_COFF_Header.sizeOfOptionalHeader);
    printf("Characteristics: 0x%.4X\n", myPEHeader->PE_COFF_Header.characteristics);
    printf("Characteristics: ");
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_RELOCS_STRIPPER)){
        printf("IMAGE_FILE_RELOCS_STRIPPER, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_EXECUTABLE_IMAGE)){
        printf("IMAGE_FILE_EXECUTABLE_IMAGE, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_LINE_NUMS_STRIPPED)){
        printf("IMAGE_FILE_LINE_NUMS_STRIPPED, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_LOCAL_SYMS_STRIPPED)){
        printf("IMAGE_FILE_LOCAL_SYMS_STRIPPED, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_AGGRESSIVE_WS_TRIM)){
        printf("IMAGE_FILE_AGGRESSIVE_WS_TRIM, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_LARGE_ADDRESS_AWARE)){
        printf("IMAGE_FILE_LARGE_ADDRESS_AWARE, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_BYTES_REVERSED_LO)){
        printf("IMAGE_FILE_BYTES_REVERSED_LO, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_32BIT_MACHINE)){
        printf("IMAGE_FILE_32BIT_MACHINE, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_DEBUG_STRIPPED)){
        printf("IMAGE_FILE_DEBUG_STRIPPED, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)){
        printf("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_NET_RUN_FROM_SWAP)){
        printf("IMAGE_FILE_NET_RUN_FROM_SWAP, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_SYSTEM)){
        printf("IMAGE_FILE_SYSTEM, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_DLL)){
        printf("IMAGE_FILE_DLL, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_UP_SYSTEM_ONLY)){
        printf("IMAGE_FILE_UP_SYSTEM_ONLY, ");
    }
    if (check_flag_16(myPEHeader->PE_COFF_Header.characteristics, IMAGE_FILE_FILE_BYTES_REVERSED_HI)){
        printf("IMAGE_FILE_FILE_BYTES_REVERSED_HI, ");
    }
    printf("\n");
    printf("----------OPTIONAL HEADER----------\n");*/
    uint16_t magic;
    fread(&magic, 1, 2, pe);
    //printf("Magic: 0x%.4X\n", magic);
    fseek(pe, -2, SEEK_CUR);
    if (magic == 0x010B){
        //printf("Found PE32\n");
        PE32_Header *myPE32Header = getPE32_Header(pe, myDOSHeader);
        /*printf("Magic: 0x%.4X\n", myPE32Header->magic);
        printf("Major Linker Version: 0x%.2X\n", myPE32Header->majorLinkerVersion);
        printf("Minor Linker Version: 0x%.2X\n", myPE32Header->minorLinkerVersion);
        printf("Size of Code: 0x%.8X\n", myPE32Header->sizeOfCode);
        printf("Size of Uninitialized Data: 0x%.8X\n", myPE32Header->sizeOfUninitializedData);
        printf("Address of Entry Point: 0x%.8X\n", myPE32Header->addressOfEntryPoint);
        printf("Base of Code 0x%.8X\n", myPE32Header->baseOfCode);
        printf("Base of Data: 0x%.8X\n", myPE32Header->baseOfData);
        printf("Image Base: 0x%.8X\n", myPE32Header->imageBase);
        printf("Section Alignment: 0x%.8X\n", myPE32Header->sectionAlignment);
        printf("File Alignment: 0x%.8X\n", myPE32Header->fileAlignment);
        printf("Major Operating System Version: 0x%.4X\n", myPE32Header->majorOperatingSystemVersion);
        printf("Minor Operating System Version: 0x%.4X\n", myPE32Header->minorOperatingSystemVersion);
        printf("Major Image Version: 0x%.4X\n", myPE32Header->majorImageVersion);
        printf("Minor Image Version: 0x%.4X\n", myPE32Header->minorImageVersion);
        printf("Major Subsystem Version: 0x%.4X\n", myPE32Header->majorSubsystemVersion);
        printf("Minor Subsystem Version: 0x%.4X\n", myPE32Header->minorSubsystemVersion);
        printf("Win32 Verison Value: 0x%.8X\n", myPE32Header->win32VersionValue);
        printf("Size of Image: 0x%.8X\n", myPE32Header->sizeOfImage);
        printf("Size of Headers: 0x%.8X\n", myPE32Header->sizeOfHeaders);
        printf("Checksum: 0x%.8X\n", myPE32Header->checkSum);
        printf("Subsystem: 0x%.4X\n", myPE32Header->subsystem);
        printf("DLL Characteristics: 0x%.4X\n", myPE32Header->dllCharacteristics);
        printf("Size of Stack Reserve: 0x%.8X\n", myPE32Header->sizeOfStackReserve);
        printf("Size of Stack Commit: 0x%.8X\n", myPE32Header->sizeOfStackCommit);
        printf("Size of Heap Reserve: 0x%.8X\n", myPE32Header->sizeOfHeapReserve);
        printf("Size of Heap Commit: 0x%.8X\n", myPE32Header->sizeOfHeapCommit);
        printf("Loader Flags: 0x%.8X\n", myPE32Header->loaderFlags);
        printf("Number of RVA and Sizes: 0x%.8X\n", myPE32Header->numberOfRvaAndSizes);
        printf("----------HEADER DATA DIRECTORIES----------\n");
        printf("Export Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.exportTable.VirtualAddress);
        printf("Export Table Size: 0x%.8X\n", myPE32Header->dataDirectories.exportTable.Size);
        printf("Import Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.importTable.VirtualAddress);
        printf("Import Table Size: 0x%.8X\n", myPE32Header->dataDirectories.importTable.Size);
        printf("Resource Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.resourceTable.VirtualAddress);
        printf("Resource Table Size: 0x%.8X\n", myPE32Header->dataDirectories.resourceTable.Size);
        printf("Exception Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.exceptionTable.VirtualAddress);
        printf("Exception Table Size: 0x%.8X\n", myPE32Header->dataDirectories.exceptionTable.Size);
        printf("Certificate Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.certificateTable.VirtualAddress);
        printf("Certificate Table Size: 0x%.8X\n", myPE32Header->dataDirectories.certificateTable.Size);
        printf("Base Relocation Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.baseRelocationTable.VirtualAddress);
        printf("Base Relocation Table Size: 0x%.8X\n", myPE32Header->dataDirectories.baseRelocationTable.Size);
        printf("Debug Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.debug.VirtualAddress);
        printf("Debug Size: 0x%.8X\n", myPE32Header->dataDirectories.debug.Size);
        printf("Global Ptr Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.globalPtr.VirtualAddress);
        printf("Global Ptr Size: 0x%.8X\n", myPE32Header->dataDirectories.globalPtr.Size);
        printf("TLS Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.TLSTable.VirtualAddress);
        printf("TLS Table Size: 0x%.8X\n", myPE32Header->dataDirectories.TLSTable.Size);
        printf("Load Config Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.loadConfigTable.VirtualAddress);
        printf("Load Config Table Size: 0x%.8X\n", myPE32Header->dataDirectories.loadConfigTable.Size);
        printf("Bound Import Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.boundImport.VirtualAddress);
        printf("Bound Import Size: 0x%.8X\n", myPE32Header->dataDirectories.boundImport.Size);
        printf("IAT Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.IAT.VirtualAddress);
        printf("IAT Size: 0x%.8X\n", myPE32Header->dataDirectories.IAT.Size);
        printf("Delay Import Descriptor Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.delayImportDescriptor.VirtualAddress);
        printf("Delay Import Descriptor Size: 0x%.8X\n", myPE32Header->dataDirectories.delayImportDescriptor.Size);
        printf("CLR Runtime Header Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.CLRRuntimeHeader.VirtualAddress);
        printf("CLR Runtime Header Size: 0x%.8X\n", myPE32Header->dataDirectories.CLRRuntimeHeader.Size);
        printf("----------EXTRA DATA DIRECTORIES----------\n");*/
        uint32_t numberOfDataDirectoriesLeft = myPE32Header->numberOfRvaAndSizes - (sizeof(Header_Data_Directory)/sizeof(IMAGE_DATA_DIRECTORY));
        //printf("Number of Data Directories Left: %d\n", numberOfDataDirectoriesLeft);
        //printf("----------SECTION TABLE----------\n");
        SectionTableNode *root = constructSectionTableLinkedList(pe, myDOSHeader, myPEHeader);
        //dumpSections(root);
        
        //char name[] = ".text";
        //SectionTableNode *text = findSectionTable(root, name);
        
        //printf("FOUND: %c%c%c%c%c%c%c%c\n", text->Section_Header.Name[0], text->Section_Header.Name[1], text->Section_Header.Name[2], text->Section_Header.Name[3], text->Section_Header.Name[4], text->Section_Header.Name[5], text->Section_Header.Name[6], text->Section_Header.Name[7]);
        
        //printf("Finding Entry Point: 0x%.16X\n", resolveEntryPoint(myPE32Header, root));
        
        
        //printf("Export Table Virtual Address: 0x%.8X\n", myPE32Header->dataDirectories.exportTable.VirtualAddress);
        //printf("Export Table Size: 0x%.8X\n", myPE32Header->dataDirectories.exportTable.Size);
        
        Export_Directory_Table *extractedExportDirectoryTable = getExportDirectoryTable(pe, root, myPE32Header);
    
        printf("Export Flags: 0x%.8X\n", extractedExportDirectoryTable->ExportFlags);
        printf("Time/Date Stamp: 0x%.8X\n", extractedExportDirectoryTable->TimeDateStamp);
        time_t theTime = extractedExportDirectoryTable->TimeDateStamp;
        struct tm ts = *localtime(&theTime);
        char buf[80];
        strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
        printf("%s\n", buf);
        printf("Major Version: 0x%.4X\n", extractedExportDirectoryTable->MajorVersion);
        printf("Minor Version: 0x%.4X\n", extractedExportDirectoryTable->MinorVersion);
        printf("Name RVA: 0x%.8X\n", extractedExportDirectoryTable->NameRVA);
        printf("Ordinal Base: 0x%.8X\n", extractedExportDirectoryTable->OrdinalBase);
        printf("Address Table Entries: 0x%.8X\n", extractedExportDirectoryTable->AddressTableEntries);
        printf("Number of Name Pointers: 0x%.8X\n", extractedExportDirectoryTable->NumberofNamePointers);
        printf("Export Address Table RVA: 0x%.8X\n", extractedExportDirectoryTable->ExportAddressTableRVA);
        printf("Name Pointer RVA: 0x%.8X\n", extractedExportDirectoryTable->NamePointerRVA);
        printf("Ordinal Table RVA: 0x%.8X\n", extractedExportDirectoryTable->OrdinalTableRVA);
        
        printf("Resolved Name RVA: 0x%.16X\n", resolveRVA(root, extractedExportDirectoryTable->NameRVA));
        fseek(pe, resolveRVA(root, extractedExportDirectoryTable->NameRVA), SEEK_SET);
        char *DLLName = malloc(500);
        fread(DLLName, 1, 500, pe);
        printf("DLL Name: %s\n", DLLName); //OMFG IT WORKED!
        free(DLLName);
        
        free(extractedExportDirectoryTable);
        freeSectionTableLinkedList(root);
        free(myPE32Header);
    }else if (magic == 0x020B){
        printf("Found PE32+\n");
    }else{
        printf("Invalid PE32 magic. Exiting!\n");
        return 1;
    }
    
    free(myPEHeader);
    free(myDOSHeader);
    fclose(pe);
    return 0;
}
