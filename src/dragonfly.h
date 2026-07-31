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
#define DF_COMMIT_MAX_LEN (2 + 3 * DF_MAX_PRIME_LEN + 255)
#define DF_CONFIRM_MAX_LEN (2 + DF_MAX_HASH_LEN)
#define DF_PK_M_LEN 16

#define DF_OK 0
#define DF_ERR_FAIL -1
#define DF_ERR_FCC_GROUP_NOT_SUPPORTED -2

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
    df_buf *anti_clogging_token;
    char *pw_id;
    int vlan_id;
    u8 bssid[ETH_ALEN];
    df_buf *own_rejected_groups;
    df_buf *peer_rejected_groups;
    u32 own_addr_higher : 1;
    os_reltime disabled_until;
} df_temporary_data;

typedef enum
{
    DF_NOTHING,
    DF_COMMITTED,
    DF_CONFIRMED,
    DF_ACCEPTED
} df_state;

typedef struct
{
    df_state state;
    u16 send_confirm;
    u8 pmk[DF_PMK_LEN_MAX];
    size_t pmk_len;
    int akmp;
    u32 own_akm_suite_selector;
    u32 peer_akm_suite_selector;
    u8 pmkid[DF_PMKID_LEN];
    crypto_bignum *peer_commit_scalar;
    crypto_bignum *peer_commit_scalar_accepted;
    int group;
    u32 sync;
    u16 rc;
    u32 h2e : 1;
    u32 pk : 1;
    df_temporary_data *tmp;
} df_data;

int dragonfly_group_allowed(df_data *df, int *allowed_groups, u16 group);

int dragonfly_prepare_commit(
    const u8 *addr1,
    const u8 *addr2,
    const u8 *password,
    size_t password_len,
    df_data *df);

#endif
