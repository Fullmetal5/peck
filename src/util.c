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
