#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "includes/pec.h"

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
    printf("WARNING: Couldn't resolve real memory address 0x%.16X\n", address + extractedPE32_Header->imageBase);
    return 0;
}

uint64_t resolveEntryPoint(PE32_Header *extractedPE32_Header, SectionTableNode *root){
    return resolveRVA(root, extractedPE32_Header->addressOfEntryPoint);
}

void getDOS_Header(PEC_FILE *thePEC_FILE){
    DOS_Header *extractedDOS_Header = (DOS_Header*)malloc(sizeof(DOS_Header));
    fseek(thePEC_FILE->RawFile, 0, SEEK_SET);
    fread(extractedDOS_Header, 1, sizeof(DOS_Header), thePEC_FILE->RawFile);
    thePEC_FILE->extractedDOS_Header = extractedDOS_Header;
}

void getPE_Header(PEC_FILE *thePEC_FILE){
    PE_Header *extractedPE_Header = (PE_Header*)malloc(sizeof(PE_Header));
    fseek(thePEC_FILE->RawFile, thePEC_FILE->extractedDOS_Header->e_lfanew, SEEK_SET);
    fread(extractedPE_Header, 1, sizeof(PE_Header), thePEC_FILE->RawFile);
    thePEC_FILE->extractedPE_Header = extractedPE_Header;
}

void getPE32_Header(PEC_FILE *thePEC_FILE){
    PE32_Header *extractedPE32_Header = (PE32_Header*)malloc(sizeof(PE32_Header));
    fseek(thePEC_FILE->RawFile, (thePEC_FILE->extractedDOS_Header->e_lfanew + sizeof(PE_Header)), SEEK_SET);
    fread(extractedPE32_Header, 1, sizeof(PE32_Header), thePEC_FILE->RawFile);
    thePEC_FILE->extractedPE32_Header = extractedPE32_Header;
}

void getExportDirectoryTable(PEC_FILE *thePEC_FILE){
    Export_Directory_Table *extractedExportDirectoryTable = (Export_Directory_Table*)malloc(sizeof(Export_Directory_Table));
    fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->root, thePEC_FILE->extractedPE32_Header->dataDirectories.exportTable.VirtualAddress), SEEK_SET);
    fread(extractedExportDirectoryTable, 1, sizeof(Export_Directory_Table), thePEC_FILE->RawFile);
    thePEC_FILE->extractedExport_Directory_Table = extractedExportDirectoryTable;
}

void constructSectionTableLinkedList(PEC_FILE *thePEC_FILE){
    if (thePEC_FILE->extractedPE_Header->PE_COFF_Header.numberOfSections == 0){
        thePEC_FILE->root = NULL;
        return;
    }
    SectionTableNode *root = (SectionTableNode*)malloc(sizeof(SectionTableNode));
    SectionTableNode *current = root;
    root->next = 0;
    fseek(thePEC_FILE->RawFile, (thePEC_FILE->extractedDOS_Header->e_lfanew + sizeof(PE_Header) + thePEC_FILE->extractedPE_Header->PE_COFF_Header.sizeOfOptionalHeader), SEEK_SET);
    fread(&root->Section_Header, 1, sizeof(SECTION_TABLE), thePEC_FILE->RawFile);
    if (thePEC_FILE->extractedPE_Header->PE_COFF_Header.numberOfSections == 1){
        thePEC_FILE->root = root;
        return;
    }
    for (int i = 1; i <= thePEC_FILE->extractedPE_Header->PE_COFF_Header.numberOfSections; i++){
        current->next = (SectionTableNode*)malloc(sizeof(SectionTableNode));
        current = current->next;
        current->next = 0;
        fread(&current->Section_Header, 1, sizeof(SECTION_TABLE), thePEC_FILE->RawFile);
    }
    thePEC_FILE->root = root;
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

//Does everything BUT run close on the file. To properly free everything make sure you close the file before passing the PEC_FILE to this function.
void freePEC_FILE(PEC_FILE *thePEC_FILE){
    if (thePEC_FILE == NULL){
        return;
    }
    if (thePEC_FILE->extractedDOS_Header){
        free(thePEC_FILE->extractedDOS_Header);
        thePEC_FILE->extractedDOS_Header = NULL;
    }
    if (thePEC_FILE->extractedPE_Header){
        free(thePEC_FILE->extractedPE_Header);
        thePEC_FILE->extractedPE_Header = NULL;
    }
    if (thePEC_FILE->extractedPE32_Header){
        free(thePEC_FILE->extractedPE32_Header);
        thePEC_FILE->extractedPE32_Header = NULL;
    }
    if (thePEC_FILE->extractedExport_Directory_Table){
        free(thePEC_FILE->extractedExport_Directory_Table);
        thePEC_FILE->extractedExport_Directory_Table = NULL;
    }
    if (thePEC_FILE->root){
        freeSectionTableLinkedList(thePEC_FILE->root);
        thePEC_FILE->root = NULL;
    }
    free(thePEC_FILE);
    thePEC_FILE = NULL;
}

int main(int argc, char *argv[]){
    if (argc != 2){
        return 0;
    }
    printf("Analysing %s\n", argv[1]);
    FILE *pe = fopen(argv[1], "r");
    //The reason this is being allocated with calloc is because there are alot of pointers in this struct and having them already set to 0 makes it way easier then having to initialize all of them all to 0 and makes it break less when a new pointer is added.
    PEC_FILE *thePEC_FILE = (PEC_FILE*)calloc(sizeof(PEC_FILE), 1);
    thePEC_FILE->RawFile = pe;
    getDOS_Header(thePEC_FILE);
    getPE_Header(thePEC_FILE);
    uint16_t magic = 0x0000;
    fread(&magic, 1, 2, thePEC_FILE->RawFile);
    fseek(thePEC_FILE->RawFile, -2, SEEK_CUR);
    if (magic == 0x010B){
        printf("Found PE32\n");
        getPE32_Header(thePEC_FILE);
        constructSectionTableLinkedList(thePEC_FILE);
        getExportDirectoryTable(thePEC_FILE);
        printf("Name RVA: 0x%.8X\n", thePEC_FILE->extractedExport_Directory_Table->NameRVA);
        printf("Resolved Name RVA: 0x%.16X\n", resolveRVA(thePEC_FILE->root, thePEC_FILE->extractedExport_Directory_Table->NameRVA));
        fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->root, thePEC_FILE->extractedExport_Directory_Table->NameRVA), SEEK_SET);
        char *DLLName = (char*)malloc(500);
        fread(DLLName, 1, 500, thePEC_FILE->RawFile);
        printf("DLL Name: %s\n", DLLName);
        free(DLLName);
        uint32_t *PENamePointerTable = (uint32_t *)malloc(sizeof(uint32_t) * thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers);
        fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->root, thePEC_FILE->extractedExport_Directory_Table->NamePointerRVA), SEEK_SET);
        fread(PENamePointerTable, 1, sizeof(uint32_t) * thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers, thePEC_FILE->RawFile);
        char *funcName = (char*)malloc(1024); //I just can't be bothered to actually read till a null byte plus getdelim doesn't exist with mingw so screw it.
        for (int i = 0; i < thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers; i++){
            uint32_t nameAddress = resolveRVA(thePEC_FILE->root, PENamePointerTable[i]);
            fseek(thePEC_FILE->RawFile, nameAddress, SEEK_SET);
            fread(funcName, 1, 1024, thePEC_FILE->RawFile);
            funcName[1023] = '\x00'; //If it's to long just truncate it.
            printf("Function Name: %s\n", funcName);
        }
        free(funcName);
        free(PENamePointerTable);
        
    }else if (magic == 0x020B){
        printf("Found PE32+\n");
    }else if (magic == 0x0107){
        printf("Found ROM Image\n");
    }else{
        printf("Invalid PE32 magic: 0x%.4X\n", magic);
    }
    fclose(pe);
    freePEC_FILE(thePEC_FILE);
    return 0;
}
