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
    SectionTableNode *root;
} PEC_FILE;

extern uint64_t resolveRVA(SectionTableNode *root, uint64_t address);
extern uint64_t resolveRealMemoryAddress(PE32_Header *extractedPE32_Header, SectionTableNode *root, uint64_t address);
extern uint64_t resolveEntryPoint(PE32_Header *extractedPE32_Header, SectionTableNode *root);
extern void getDOS_Header(PEC_FILE *thePEC_FILE);
extern void getPE_Header(PEC_FILE *thePEC_FILE);
extern void getPE32_Header(PEC_FILE *thePEC_FILE);
extern void getExportDirectoryTable(PEC_FILE *thePEC_FILE);
extern void constructSectionTableLinkedList(PEC_FILE *thePEC_FILE);
extern void freeSectionTableLinkedList(SectionTableNode *root);
extern SectionTableNode* findSectionTable(SectionTableNode *root, char name[8]);
extern void dumpSections(SectionTableNode *root);
extern void freePEC_FILE(PEC_FILE *thePEC_FILE);

#endif
