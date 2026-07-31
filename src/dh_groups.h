/*
 * Diffie-Hellman groups
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DF_DH_GROUPS_H
#define DF_DH_GROUPS_H

#include "common.h"

typedef struct
{
    int id;
    const u8 *generator;
    size_t generator_len;
    const u8 *prime;
    size_t prime_len;
    const u8 *order;
    size_t order_len;
    u32 safe_prime : 1;
} dh_group;

const dh_group *dh_groups_get(int id);

#endif
