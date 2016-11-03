typedef struct _DOS_Header {
    char signature[2];
    uint16_t lastPage;
    uint16_t pages;
    uint16_t relocationItems;
    uint16_t headerSize;
    uint16_t minAlloc;
    uint16_t maxAlloc;
    uint16_t SS;
    uint16_t SP;
    uint16_t checksum;
    uint16_t IP;
    uint16_t CS;
    uint16_t relocationTable;
    uint16_t overlay;
    uint16_t reserved1[4];
    uint16_t oem_id;
    uint16_t oem_info;
    uint16_t reserved2[10];
    uint32_t e_lfanew;
} __attribute__((packed)) DOS_Header;

typedef struct _DOS_Reloc {
    uint16_t offset;
    uint16_t segment;
} __attribute__((packed)) DOS_Reloc;
