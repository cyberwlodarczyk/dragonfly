/*
 * wpa_supplicant/hostapd / common helper functions, etc.
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DF_COMMON_H
#define DF_COMMON_H

#include "os.h"

#include <stdint.h>
#include <stddef.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#define BIT(x) (1U << (x))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static inline void PUT_LE16(u8 *a, u16 val)
{
    a[1] = (u8)(val >> 8);
    a[0] = (u8)(val & 0xff);
}

void forced_memzero(void *ptr, size_t len);

void bin_clear_free(void *bin, size_t len);

void buf_shift_right(u8 *buf, size_t len, size_t bits);

#endif
