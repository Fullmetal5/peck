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
