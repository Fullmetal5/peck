#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pe.h"

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
        printf("Name RVA: 0x%.8X\n", thePEC_FILE->extractedExport_Directory_Table->NameRVA);
        printf("Resolved Name RVA: 0x%.16X\n", resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->NameRVA));
        fseek(thePEC_FILE->RawFile, resolveRVA(thePEC_FILE->SectionTableLinkedList, thePEC_FILE->extractedExport_Directory_Table->NameRVA), SEEK_SET);
        char *DLLName = (char*)malloc(500);
        fread(DLLName, 1, 500, thePEC_FILE->RawFile);
        printf("DLL Name: %s\n", DLLName);
        free(DLLName);
        populateNameArray(thePEC_FILE);
        populateOrdinalArray(thePEC_FILE);
        populateExportArray(thePEC_FILE);
        char *ForwardedName = (char*)malloc(500);
        for (int i = 0; i < thePEC_FILE->extractedExport_Directory_Table->NumberofNamePointers; i++){
            uint16_t ordinal = thePEC_FILE->Export_Directory_Ordinal_Array[i];
            uint16_t realOrdinal = ordinal-thePEC_FILE->extractedExport_Directory_Table->OrdinalBase + 1; //This couldn't make sense unless you add 1 but the documentation doesn't say anything about it :/
            uint32_t ExportorForwarderRVA = thePEC_FILE->Export_Address_Array[realOrdinal];
            printf("Function Name:           %s\n", thePEC_FILE->Export_Directory_Name_Array[i]);
            printf("Name/Ordinal Index:      %d\n", i);
            printf("Maps to ordinal:         %d\n", ordinal);
            printf("Export Index:            %d\n", realOrdinal);
            printf("Export or Forwarder RVA: 0x%.8X\n", ExportorForwarderRVA);
            if (isValidForwarderRVA(thePEC_FILE, ExportorForwarderRVA)){
                printf("This is a forwarder RVA\n");
                uint64_t resolvedForwarder = resolveRVA(thePEC_FILE->SectionTableLinkedList, ExportorForwarderRVA);
                printf("Resolved Forwarder RVA:  0x%.16X\n", resolvedForwarder);
                fseek(thePEC_FILE->RawFile, resolvedForwarder, SEEK_SET);
                fread(ForwardedName, 1, 500, thePEC_FILE->RawFile);
                ForwardedName[499] = '\x00';
                printf("Forwarded Name:          %s\n", ForwardedName);
            }else{
                printf("This is an export RVA\n");
            }
        }
        free(ForwardedName);
    }else if (magic == 0x020B){
        printf("Found PE32+\n");
    }else if (magic == 0x0107){
        printf("Found ROM Image\n");
    }else{
        printf("Invalid PE32 magic: 0x%.4X\n", magic);
    }
    fclose(thePEC_FILE->RawFile);
    freePEC_FILE(thePEC_FILE);
    return 0;
}
