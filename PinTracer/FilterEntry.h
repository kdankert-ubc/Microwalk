#pragma once

#include <stdint.h>

typedef uint8_t FilterType;

#define FilterTypeWhiteList         1 << 0
#define FilterTypeControlFlow       1 << 1
#define FilterTypeDataAccess        1 << 2

#define FilterTypeJump              1 << 4
#define FilterTypeCall              1 << 5
#define FilterTypeReturn            1 << 6
#define FilterTypeLinearize         1 << 7

#define FilterTypeRead              1 << 6
#define FilterTypeWrite             1 << 7

typedef struct FilterEntry {
    FilterType type;
    uintptr_t originStart;
    uintptr_t originEnd;
    uintptr_t targetStart;
    uintptr_t targetEnd;
} FilterEntry;

#define FilterTypeMatch(type, value) (((type) & (value)) == (type))
