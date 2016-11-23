#include "pe.h"
#include "coff.h"
#include "dos.h"

#ifndef _PEC_H_
#define _PEC_H_

typedef struct _SectionTableNode {
    SECTION_TABLE Section_Header;
    struct SectionTableNode *next;
} __attribute__((packed)) SectionTableNode;

typedef struct _PEC_FILE {
    FILE *RawFile;
    DOS_Header *extractedDOS_Header;
    PE_Header *extractedPE_Header;
    PE32_Header *extractedPE32_Header;
    Export_Directory_Table *extractedExport_Directory_Table;
    SectionTableNode *root;
} PEC_FILE;

#endif
