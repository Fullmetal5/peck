#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pe_struct.h"
#include "util.h"

#ifndef PE_H
#define PE_H

typedef struct PEC_FILE {
    FILE *RawFile;
    DOS_Header *extractedDOS_Header;
    PE_Header *extractedPE_Header;
    PE32_Header *extractedPE32_Header;
    Export_Directory_Table *extractedExport_Directory_Table;
    SectionTableNode *SectionTableLinkedList;
    char **Export_Directory_Name_Array;
    uint16_t *Export_Directory_Ordinal_Array;
    uint32_t *Export_Address_Array;
} PEC_FILE;

extern uint64_t resolveRVA(SectionTableNode *SectionTableLinkedList, uint64_t address);
extern uint64_t resolveRealMemoryAddress(PE32_Header *extractedPE32_Header, SectionTableNode *SectionTableLinkedList, uint64_t address);
extern uint64_t resolveEntryPoint(PE32_Header *extractedPE32_Header, SectionTableNode *SectionTableLinkedList);
extern void populateDOS_Header(PEC_FILE *thePEC_FILE);
extern void populatePE_Header(PEC_FILE *thePEC_FILE);
extern void populatePE32_Header(PEC_FILE *thePEC_FILE);
extern void populateExportDirectoryTable(PEC_FILE *thePEC_FILE);
extern void constructSectionTableLinkedList(PEC_FILE *thePEC_FILE);
extern void freeSectionTableLinkedList(SectionTableNode *SectionTableLinkedList);
extern SectionTableNode* findSectionTable(SectionTableNode *SectionTableLinkedList, char name[8]);
extern int isValidForwarderRVA(PEC_FILE *thePEC_FILE, uint32_t ForwarderRVA);
extern void dumpSections(SectionTableNode *SectionTableLinkedList);
extern void populateNameArray(PEC_FILE *thePEC_FILE);
extern void populateOrdinalArray(PEC_FILE *thePEC_FILE);
extern void populateExportArray(PEC_FILE *thePEC_FILE);
extern void freePEC_FILE(PEC_FILE *thePEC_FILE);

#endif
