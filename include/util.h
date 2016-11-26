#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef UTIL_H
#define UTIL_H

extern int check_flag_8(uint8_t flags, uint8_t flagToCheck);
extern int check_flag_16(uint16_t flags, uint16_t flagToCheck);
extern int check_flag_32(uint32_t flags, uint32_t flagToCheck);
extern int check_flag_64(uint64_t flags, uint64_t flagToCheck);

//Copies till the byte is found or length is reached. Returns number of bytes copied. DOESN'T NULL TERMINATE STRING
extern int copyTillByte(void* dest, char byte, int length, void* src);

extern void* readTillByte(void* dest, char byte, int length, int* bytesCopied, FILE* src);

char* copyStringFromFile(FILE* src);

#endif
