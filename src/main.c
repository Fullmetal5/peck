#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pe.h"
#include "util.h"

void cleanup(PEC_FILE *thePEC_FILE){
    fclose(thePEC_FILE->RawFile);
    freePEC_FILE(thePEC_FILE);
}

void dumpExportTable(PEC_FILE *thePEC_FILE){
    char *ForwardedDLLName = (char*)malloc(1024);
    char *ForwardedFuncName = (char*)malloc(1024);
    for (int i = 0; i < thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers; i++){
        printf("=======================================================================\n");
        uint16_t ordinal = thePEC_FILE->Export_Directory_Ordinal_Array[i];
        uint16_t realOrdinal = ordinal-thePEC_FILE->extractedExport_Directory_Table->OrdinalBase + 1; //This couldn't make sense unless you add 1 but the documentation doesn't say anything about it :/
        if (realOrdinal >= thePEC_FILE->extractedExport_Directory_Table->AddressTableEntries){
            printf("WARNING: Invalid realOrdinal when indexing into Export_Address_Array\n");
            printf("Function Name:           %s\n", thePEC_FILE->Export_Directory_Name_Array[i]);
            printf("Name/Ordinal Index:      %d\n", i);
            printf("Maps to ordinal:         %d\n", ordinal);
            printf("Real ordinal:            %d\n", realOrdinal);
            printf("Aborting dump of export tables\n");
            free(ForwardedDLLName);
            free(ForwardedFuncName);
            printf("Aborted with %d iterations left in NumberofNamePointer loop out of %d ordinals in total\n", thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers-i, thePEC_FILE->extractedExport_Directory_Table->AddressTableEntries);
            return;
        }
        uint32_t ExportorForwarderRVA = thePEC_FILE->Export_Address_Array[realOrdinal];
        printf("Function Name:           %s\n", thePEC_FILE->Export_Directory_Name_Array[i]);
        printf("Name/Ordinal Index:      %d\n", i);
        printf("Maps to ordinal:         %d\n", ordinal);
        printf("Real ordinal:            %d\n", realOrdinal);
        printf("Export or Forwarder RVA: 0x%.8X\n", ExportorForwarderRVA);
        if (isValidForwarderRVA(thePEC_FILE, ExportorForwarderRVA)){
            printf("This is a Forwarder RVA\n");
            uint64_t resolvedForwarder = resolveRVA(thePEC_FILE->SectionTableLinkedList, ExportorForwarderRVA);
            printf("Resolved Forwarder RVA:  0x%.16X\n", resolvedForwarder);
            fseek(thePEC_FILE->RawFile, resolvedForwarder, SEEK_SET);
            char *ForwardedName = copyStringFromFile(thePEC_FILE->RawFile);
            printf("Forwarded Name:          %s\n", ForwardedName);
            int bytesCopied = copyTillByte(ForwardedDLLName, '.', 1024, ForwardedName);
            ForwardedDLLName[bytesCopied] = '\x00';
            printf("Forwarded DLL Name:      %s\n", ForwardedDLLName);
            bytesCopied = copyTillByte(ForwardedFuncName, '\x00', 1024, ForwardedName + bytesCopied + 1);
            ForwardedFuncName[bytesCopied] = '\x00';
            printf("Forwarded Function Name: %s\n", ForwardedFuncName);
            free(ForwardedName);
        }else{
            printf("This is an Export RVA\n");
            uint64_t resolvedExport = resolveRVA(thePEC_FILE->SectionTableLinkedList, ExportorForwarderRVA);
            printf("Export Address:          0x%.16X\n", resolvedExport);
        }
        printf("=======================================================================\n");
    }
    free(ForwardedDLLName);
    free(ForwardedFuncName);
    printf("There are %d ordinal only exports\n", thePEC_FILE->extractedExport_Directory_Table->AddressTableEntries - thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers);
}

int main(int argc, char *argv[]){
    if (argc != 2){
        return 0;
    }
    printf("Analysing %s\n", argv[1]);
    //The reason this is being allocated with calloc is because there are alot of pointers in this struct and having them already set to 0 makes it way easier then having to initialize all of them all to 0 and makes it break less when a new pointer is added.
    PEC_FILE *thePEC_FILE = (PEC_FILE*)calloc(sizeof(PEC_FILE), 1);
    thePEC_FILE->RawFile = fopen(argv[1], "r");
    populateDOS_Header(thePEC_FILE);
    populatePE_Header(thePEC_FILE);
    uint16_t magic = 0x0000;
    fread(&magic, 1, 2, thePEC_FILE->RawFile);
    fseek(thePEC_FILE->RawFile, -2, SEEK_CUR);
    if (magic == 0x010B){
        printf("Found PE32\n");
        populatePE32_Header(thePEC_FILE);
        constructSectionTableLinkedList(thePEC_FILE);
        populateExportDirectoryTable(thePEC_FILE);
        if (thePEC_FILE->extractedExport_Directory_Table == NULL){
            cleanup(thePEC_FILE);
            return 0;
        }
        printf("Name RVA: 0x%.8X\n", thePEC_FILE->extractedExport_Directory_Table->NameRVA);
        printf("Resolved Name RVA: 0x%.16X\n", resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->NameRVA));
        fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->NameRVA), SEEK_SET);
        char* DLLName = copyStringFromFile(thePEC_FILE->RawFile);
        printf("DLL Name: %s\n", DLLName);
        free(DLLName);
        printf("Populating name array\n");
        populateNameArray(thePEC_FILE);
        printf("Populating ordinal array\n");
        populateOrdinalArray(thePEC_FILE);
        printf("Populating export array\n");
        populateExportArray(thePEC_FILE);
        dumpExportTable(thePEC_FILE);
    }else if (magic == 0x020B){
        printf("Found PE32+\n");
    }else if (magic == 0x0107){
        printf("Found ROM Image\n");
    }else{
        printf("Invalid PE32 magic: 0x%.4X\n", magic);
    }
    cleanup(thePEC_FILE);
    return 0;
}
