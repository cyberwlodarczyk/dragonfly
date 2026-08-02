/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DF_H
#define DF_H

#include "common.h"

#include "buf.h"
#include "crypto.h"
#include "dh_groups.h"

#define DF_KCK_LEN 32
#define DF_PMK_LEN 32
#define DF_PMK_LEN_MAX 64
#define DF_PMKID_LEN 16
#define DF_MAX_PRIME_LEN 512
#define DF_MAX_ECC_PRIME_LEN 66
#define DF_MAX_HASH_LEN 64
#define DF_COMMIT_MAX_LEN (3 * DF_MAX_PRIME_LEN)
#define DF_CONFIRM_MAX_LEN DF_MAX_HASH_LEN

typedef struct
{
    u8 kck[DF_MAX_HASH_LEN];
    size_t kck_len;
    crypto_bignum *own_commit_scalar;
    crypto_bignum *own_commit_element_ffc;
    crypto_ec_point *own_commit_element_ecc;
    crypto_bignum *peer_commit_element_ffc;
    crypto_ec_point *peer_commit_element_ecc;
    crypto_ec_point *pwe_ecc;
    crypto_bignum *pwe_ffc;
    crypto_bignum *rand;
    crypto_ec *ec;
    size_t prime_len;
    size_t order_len;
    const dh_group *dh;
    const crypto_bignum *prime;
    const crypto_bignum *order;
    crypto_bignum *prime_buf;
    crypto_bignum *order_buf;
} df_temporary_data;

typedef struct
{
    u8 pmk[DF_PMK_LEN_MAX];
    size_t pmk_len;
    u8 pmkid[DF_PMKID_LEN];
    crypto_bignum *peer_commit_scalar;
    int group;
    df_temporary_data *tmp;
} df_data;

int dragonfly_set_group(df_data *df, int group);

int dragonfly_commit(
    const u8 *aid,
    const u8 *bid,
    const size_t id_len,
    const u8 *password,
    size_t password_len,
    df_data *df,
    df_buf *buf);

int dragonfly_process_commit(df_data *df, const u8 *buf, size_t len);

int dragonfly_confirm(df_data *df, df_buf *buf);

int dragonfly_check_confirm(df_data *df, const u8 *buf, size_t len);

#endif
