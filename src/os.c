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
