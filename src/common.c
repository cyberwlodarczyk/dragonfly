/*
 * wpa_supplicant/hostapd / common helper functions, etc.
 * Copyright (c) 2002-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "common.h"

#include <string.h>

/* Try to prevent most compilers from optimizing out clearing of memory that
 * becomes unaccessible after this function is called. This is mostly the case
 * for clearing local stack variables at the end of a function. This is not
 * exactly perfect, i.e., someone could come up with a compiler that figures out
 * the pointer is pointing to memset and then end up optimizing the call out, so
 * try go a bit further by storing the first octet (now zero) to make this even
 * a bit more difficult to optimize out. Once memset_s() is available, that
 * could be used here instead. */
static void *(*const volatile memset_func)(void *, int, size_t) = memset;
static u8 forced_memzero_val;

void forced_memzero(void *ptr, size_t len)
{
    memset_func(ptr, 0, len);
    if (len != 0)
    {
        forced_memzero_val = ((u8 *)ptr)[0];
    }
}

void bin_clear_free(void *bin, size_t len)
{
    if (bin != NULL)
    {
        forced_memzero(bin, len);
        os_free(bin);
    }
}

void buf_shift_right(u8 *buf, size_t len, size_t bits)
{
    for (size_t i = len - 1; i > 0; i--)
    {
        buf[i] = (buf[i - 1] << (8 - bits)) | (buf[i] >> bits);
    }
    buf[0] >>= bits;
}
