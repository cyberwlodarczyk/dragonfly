/*
 * OS specific functions for UNIX/POSIX systems
 * Copyright (c) 2005-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "os.h"

#include <stdlib.h>
#include <string.h>
#include "common.h"

int os_memcmp_const(const void *a, const void *b, size_t len)
{
    const u8 *aa = a;
    const u8 *bb = b;
    u8 res = 0;
    for (size_t i = 0; i < len; i++)
    {
        res |= aa[i] ^ bb[i];
    }
    return res;
}

void *os_zalloc(size_t size)
{
    void *ptr = os_malloc(size);
    if (ptr != NULL)
    {
        os_memset(ptr, 0, size);
    }
    return ptr;
}

void os_free(void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    free(ptr);
}
