/*
 * OS specific functions
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DF_OS_H
#define DF_OS_H

#include <stddef.h>
#include <string.h>

#define os_strlen(s) strlen(s)

#define os_memcpy(dst, src, n) memcpy((dst), (src), (n))

#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))

#define os_memset(s1, s2, n) memset((s1), (s2), (n))

#define os_malloc(s) malloc((s))

int os_memcmp_const(const void *a, const void *b, size_t len);

void *os_zalloc(size_t size);

void os_free(void *ptr);

#endif
