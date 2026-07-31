/*
 * SHA256 hash implementation and interface functions
 * Copyright (c) 2003-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SHA256_H
#define SHA256_H

#include "common.h"

#define SHA256_MAC_LEN 32

int sha256_prf(
    const u8 *key,
    size_t key_len,
    const char *label,
    const u8 *data,
    size_t data_len,
    u8 *buf,
    size_t buf_len);

int sha256_prf_bits(
    const u8 *key,
    size_t key_len,
    const char *label,
    const u8 *data,
    size_t data_len,
    u8 *buf,
    size_t buf_len_bits);

#endif
