#include "util.h"

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

int copyTillByte(void* dest, char byte, int length, void* src){
    int i = 0;
    for (; i < length; i++){
        if (((char*)src)[i] == byte){
            return i;
        }
        ((char*)dest)[i] = ((char*)src)[i];
    }
    return i;
}

//Reads from file until byte is found or until length bytes. If dest is NULL then this will allocate length space and use that. If dest is NULL and length is 0 then this function will determine how much space is it needs and use that.
//This function returns the destination it ended up using, not necessarily the one it was passed.
//If length is hit with no byte detected then this function will return NULL.
//If EOF is hit before length is reached then this function will return NULL.
//dest = Pointer to destination. If NULL then space will be allocated automatically.
//byte = Byte to look for when reading file.
//length = Number of bytes to copy. If 0 then copy until byte if found.
//bytesCopied = Pointer to variable where the total number of bytes copied will be stored on completion. If NULL then this value is ignored.
//src = Open file handle to read from. This should be already seeked to the location where reading should begin.
void* readTillByte(void* dest, char byte, int length, int* bytesCopied, FILE* src){
    if (src == NULL){
        return NULL;
    }
    int allocateDynamically = 0;
    int fakeBytesCopied = 0;
    if (bytesCopied == NULL){
        bytesCopied = &fakeBytesCopied;
    }
    *bytesCopied = 0;
    if (dest == NULL){
        dest = malloc(1);
        allocateDynamically = 1;
    }
    char byteRead = 0;
    if (length != 0){
        for (; (*bytesCopied) < length; *bytesCopied = (*bytesCopied) + 1){
            int retValue = fread(&byteRead, 1, 1, src);
            if (retValue != 1){
                printf("ERROR (retValue)\n");
                if (allocateDynamically){
                    printf("Freeing memory\n");
                    free(dest);
                }
                return NULL;
            }
            if (byteRead == byte){
                return dest;
            }
            if (allocateDynamically){
                dest = realloc(dest, (*bytesCopied) + 1);
            }
            ((char*)dest)[*bytesCopied] = byteRead;
        }
    }else{
        while (1){
            int retValue = fread(&byteRead, 1, 1, src);
            if (retValue != 1){
                printf("ERROR (retValue)\n");
                if (allocateDynamically){
                    printf("Freeing memory\n");
                    free(dest);
                }
                return NULL;
            }
            if (byteRead == byte){
                return dest;
            }
            if (allocateDynamically){
                dest = realloc(dest, (*bytesCopied) + 1);
            }
            ((char*)dest)[*bytesCopied] = byteRead;
            *bytesCopied = (*bytesCopied) + 1;
        }
    }
}

char* copyStringFromFile(FILE* src){
    int bytesCopied = 0;
    char *string = readTillByte(NULL, '\x00', 0, &bytesCopied, src);
    if (string == NULL){
        printf("Error reading string from file!\n");
        return NULL;
    }
    string = realloc(string, bytesCopied + 1);
    string[bytesCopied] = '\x00';
    return string;
}
