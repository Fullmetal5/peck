typedef struct _PEC_FILE {
    FILE *RawFile;
    uint32_t FileType;
} PEC_FILE;

//PEC_File.FileType
uint32_t FILE_TYPE_UNKNOWN      = 0x00000000;
uint32_t FILE_TYPE_PE32         = 0x00000001;
uint32_t FILE_TYPE_PE32_PLUS    = 0x00000002;
//End
