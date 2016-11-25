#include "pe.h"

//The documentation only uses RVAs relative to the Base Image address so we don't account for it here.
//This should not be used to resolve real memory address of the program!
uint64_t resolveRVA(SectionTableNode *SectionTableLinkedList, uint64_t address){
    SectionTableNode *current = SectionTableLinkedList;
    while (current != 0){
        uint32_t startAddress = current->Section_Header.VirtualAddress;
        uint32_t endAddress   = startAddress + current->Section_Header.VirtualSize;
        if ((startAddress < address) && (address < endAddress)){
            return address - startAddress + current->Section_Header.PointerToRawData;
        }
        current = current->next;
    }
    printf("WARNING: Couldn't resolve RVA 0x%.16X\n", address);
    return 0;
}

//Use this for resolving real memory addresses!
uint64_t resolveRealMemoryAddress(PE32_Header *extractedPE32_Header, SectionTableNode *SectionTableLinkedList, uint64_t address){
    address = address - extractedPE32_Header->imageBase;
    SectionTableNode *current = SectionTableLinkedList;
    while (current != 0){
        uint32_t startAddress = current->Section_Header.VirtualAddress;
        uint32_t endAddress   = startAddress + current->Section_Header.VirtualSize;
        if ((startAddress < address) && (address < endAddress)){
            return address - startAddress + current->Section_Header.PointerToRawData;
        }
        current = current->next;
    }
    printf("WARNING: Couldn't resolve real memory address 0x%.16X\n", address + extractedPE32_Header->imageBase);
    return 0;
}

uint64_t resolveEntryPoint(PE32_Header *extractedPE32_Header, SectionTableNode *SectionTableLinkedList){
    return resolveRVA(SectionTableLinkedList, extractedPE32_Header->addressOfEntryPoint);
}

void populateDOS_Header(PEC_FILE *thePEC_FILE){
    DOS_Header *extractedDOS_Header = (DOS_Header*)malloc(sizeof(DOS_Header));
    fseek(thePEC_FILE->RawFile, 0, SEEK_SET);
    fread(extractedDOS_Header, 1, sizeof(DOS_Header), thePEC_FILE->RawFile);
    thePEC_FILE->extractedDOS_Header = extractedDOS_Header;
}

void populatePE_Header(PEC_FILE *thePEC_FILE){
    PE_Header *extractedPE_Header = (PE_Header*)malloc(sizeof(PE_Header));
    fseek(thePEC_FILE->RawFile, thePEC_FILE->extractedDOS_Header->e_lfanew, SEEK_SET);
    fread(extractedPE_Header, 1, sizeof(PE_Header), thePEC_FILE->RawFile);
    thePEC_FILE->extractedPE_Header = extractedPE_Header;
}

void populatePE32_Header(PEC_FILE *thePEC_FILE){
    PE32_Header *extractedPE32_Header = (PE32_Header*)malloc(sizeof(PE32_Header));
    fseek(thePEC_FILE->RawFile, (thePEC_FILE->extractedDOS_Header->e_lfanew + sizeof(PE_Header)), SEEK_SET);
    fread(extractedPE32_Header, 1, sizeof(PE32_Header), thePEC_FILE->RawFile);
    thePEC_FILE->extractedPE32_Header = extractedPE32_Header;
}

void populateExportDirectoryTable(PEC_FILE *thePEC_FILE){
    Export_Directory_Table *extractedExportDirectoryTable = (Export_Directory_Table*)malloc(sizeof(Export_Directory_Table));
    fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedPE32_Header->dataDirectories.exportTable.VirtualAddress), SEEK_SET);
    fread(extractedExportDirectoryTable, 1, sizeof(Export_Directory_Table), thePEC_FILE->RawFile);
    thePEC_FILE->extractedExport_Directory_Table = extractedExportDirectoryTable;
}

void constructSectionTableLinkedList(PEC_FILE *thePEC_FILE){
    if (thePEC_FILE->extractedPE_Header->PE_COFF_Header.numberOfSections == 0){
        thePEC_FILE->SectionTableLinkedList = NULL;
        return;
    }
    SectionTableNode *SectionTableLinkedList = (SectionTableNode*)malloc(sizeof(SectionTableNode));
    SectionTableNode *current = SectionTableLinkedList;
    SectionTableLinkedList->next = 0;
    fseek(thePEC_FILE->RawFile, (thePEC_FILE->extractedDOS_Header->e_lfanew + sizeof(PE_Header) + thePEC_FILE->extractedPE_Header->PE_COFF_Header.sizeOfOptionalHeader), SEEK_SET);
    fread(&SectionTableLinkedList->Section_Header, 1, sizeof(SECTION_TABLE), thePEC_FILE->RawFile);
    if (thePEC_FILE->extractedPE_Header->PE_COFF_Header.numberOfSections == 1){
        thePEC_FILE->SectionTableLinkedList = SectionTableLinkedList;
        return;
    }
    for (int i = 1; i <= thePEC_FILE->extractedPE_Header->PE_COFF_Header.numberOfSections; i++){
        current->next = (SectionTableNode*)malloc(sizeof(SectionTableNode));
        current = current->next;
        current->next = 0;
        fread(&current->Section_Header, 1, sizeof(SECTION_TABLE), thePEC_FILE->RawFile);
    }
    thePEC_FILE->SectionTableLinkedList = SectionTableLinkedList;
}

void freeSectionTableLinkedList(SectionTableNode *SectionTableLinkedList){
    SectionTableNode *previous = SectionTableLinkedList;
    SectionTableNode *current = SectionTableLinkedList;
    while (current != 0){
        current = current->next;
        free(previous);
        previous = current;
    }
}

//WARNING Make sure the string you pass is UTF-8!
SectionTableNode* findSectionTable(SectionTableNode *SectionTableLinkedList, char name[8]){
    SectionTableNode *current = SectionTableLinkedList;
    while (current != 0){
        if (strncmp(current->Section_Header.Name, name, 8) == 0){
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int isValidForwarderRVA(PEC_FILE *thePEC_FILE, uint32_t ForwarderRVA){
    uint32_t startAddress = thePEC_FILE->extractedPE32_Header->dataDirectories.exportTable.VirtualAddress;
    uint32_t endAddress   = startAddress + thePEC_FILE->extractedPE32_Header->dataDirectories.exportTable.Size;
    //printf("0x%.64X\n0x%.64X\n0x%.64X\n", startAddress, ForwarderRVA, endAddress);
    if ((startAddress < ForwarderRVA) && (ForwarderRVA < endAddress)){
        //printf("Good RVA\n");
        return 1;
    }else{
        //printf("Bad RVA\n");
        return 0;
    }
}

void dumpSections(SectionTableNode *SectionTableLinkedList){
    if (SectionTableLinkedList == NULL)
        return;
    SectionTableNode *current = SectionTableLinkedList;
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

void populateNameArray(PEC_FILE *thePEC_FILE){
    thePEC_FILE->Export_Directory_Name_Array = malloc(thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers * sizeof(char*));
    uint32_t *PENamePointerTable = malloc(sizeof(uint32_t) * thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers);
    fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->NamePointerRVA), SEEK_SET);
    fread(PENamePointerTable, 1, sizeof(uint32_t) * thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers, thePEC_FILE->RawFile);
    for (int i = 0; i < thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers; i++){
        thePEC_FILE->Export_Directory_Name_Array[i] = malloc(1024 * sizeof(char)); //1024 byte limit on function names
        uint32_t nameAddress = resolveRVA(thePEC_FILE->SectionTableLinkedList, PENamePointerTable[i]);
        fseek(thePEC_FILE->RawFile, nameAddress, SEEK_SET);
        fread(thePEC_FILE->Export_Directory_Name_Array[i], 1, 1024, thePEC_FILE->RawFile);
        thePEC_FILE->Export_Directory_Name_Array[i][1023] = '\x00'; //Make sure things are null terminated
    }
    free(PENamePointerTable);
}

void populateOrdinalArray(PEC_FILE *thePEC_FILE){
    thePEC_FILE->Export_Directory_Ordinal_Array = malloc(thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers * sizeof(uint16_t));
    fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->OrdinalTableRVA), SEEK_SET);
    fread(thePEC_FILE->Export_Directory_Ordinal_Array, 1, sizeof(uint16_t) * thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers, thePEC_FILE->RawFile);
}

void populateExportArray(PEC_FILE *thePEC_FILE){
    thePEC_FILE->Export_Address_Array = malloc(thePEC_FILE->extractedExport_Directory_Table->AddressTableEntries * sizeof(uint32_t));
    fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->ExportAddressTableRVA), SEEK_SET);
    fread(thePEC_FILE->Export_Address_Array, 1, thePEC_FILE->extractedExport_Directory_Table->AddressTableEntries * sizeof(uint32_t), thePEC_FILE->RawFile);
}

//Does everything BUT run close on the file. To properly free everything make sure you close the RawFile before passing the PEC_FILE to this function.
void freePEC_FILE(PEC_FILE *thePEC_FILE){
    if (thePEC_FILE == NULL){
        return;
    }
    if (thePEC_FILE->Export_Directory_Name_Array){
        for (int i = 0; i < thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers; i++){
            free(thePEC_FILE->Export_Directory_Name_Array[i]);
        }
        free(thePEC_FILE->Export_Directory_Name_Array);
        thePEC_FILE->Export_Directory_Name_Array = NULL;
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
    if (thePEC_FILE->SectionTableLinkedList){
        freeSectionTableLinkedList(thePEC_FILE->SectionTableLinkedList);
        thePEC_FILE->SectionTableLinkedList = NULL;
    }
    if (thePEC_FILE->Export_Directory_Ordinal_Array){
        free(thePEC_FILE->Export_Directory_Ordinal_Array);
        thePEC_FILE->Export_Directory_Ordinal_Array = NULL;
    }
    if (thePEC_FILE->Export_Address_Array){
        free(thePEC_FILE->Export_Address_Array);
        thePEC_FILE->Export_Address_Array = NULL;
    }
    free(thePEC_FILE);
    thePEC_FILE = NULL;
}
