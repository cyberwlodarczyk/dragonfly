/*
 * Wrapper functions for crypto libraries
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DF_CRYPTO_H
#define DF_CRYPTO_H

#include "common.h"

#include <openssl/bn.h>
#include <openssl/ec.h>

int hmac_sha256_vector(
    const u8 *key,
    size_t key_len,
    size_t num_elem,
    const u8 *addr[],
    const size_t *len,
    u8 *mac);

int hmac_sha256(
    const u8 *key,
    size_t key_len,
    const u8 *data,
    size_t data_len,
    u8 *mac);

typedef BIGNUM crypto_bignum;

crypto_bignum *crypto_bignum_init(void);

crypto_bignum *crypto_bignum_init_set(const u8 *buf, size_t len);

crypto_bignum *crypto_bignum_init_uint(u32 val);

int crypto_bignum_to_bin(
    const crypto_bignum *a,
    u8 *buf,
    size_t buflen,
    size_t padlen);

int crypto_bignum_rand(crypto_bignum *r, const crypto_bignum *m);

int crypto_bignum_rshift(
    const crypto_bignum *a,
    int n,
    crypto_bignum *r);

int crypto_bignum_cmp(const crypto_bignum *a, const crypto_bignum *b);

int crypto_bignum_add(const crypto_bignum *a,
                      const crypto_bignum *b,
                      crypto_bignum *c);

int crypto_bignum_sub(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c);

int crypto_bignum_mod(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c);

int crypto_bignum_mulmod(const crypto_bignum *a,
                         const crypto_bignum *b,
                         const crypto_bignum *c,
                         crypto_bignum *d);

int crypto_bignum_exptmod(
    const crypto_bignum *a,
    const crypto_bignum *b,
    const crypto_bignum *c,
    crypto_bignum *d);

int crypto_bignum_div(const crypto_bignum *a,
                      const crypto_bignum *b,
                      crypto_bignum *c);

int crypto_bignum_inverse(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c);

int crypto_bignum_legendre(const crypto_bignum *a, const crypto_bignum *p);

int crypto_bignum_is_zero(const crypto_bignum *a);

int crypto_bignum_is_one(const crypto_bignum *a);

int crypto_bignum_is_odd(const crypto_bignum *a);

void crypto_bignum_deinit(crypto_bignum *n, int clear);

typedef struct
{
    EC_GROUP *group;
    int nid;
    int iana_group;
    BN_CTX *bnctx;
    BIGNUM *prime;
    BIGNUM *order;
    BIGNUM *a;
    BIGNUM *b;
} crypto_ec;

typedef EC_POINT crypto_ec_point;

crypto_ec_point *crypto_ec_point_init(crypto_ec *e);

int crypto_ec_point_mul(
    crypto_ec *e,
    const crypto_ec_point *p,
    const crypto_bignum *b,
    crypto_ec_point *res);

int crypto_ec_point_invert(crypto_ec *e, crypto_ec_point *p);

void crypto_ec_point_deinit(crypto_ec_point *p, int clear);

crypto_ec *crypto_ec_init(int group);

const crypto_bignum *crypto_ec_get_prime(crypto_ec *e);

size_t crypto_ec_prime_len(crypto_ec *e);

size_t crypto_ec_prime_len_bits(crypto_ec *e);

const crypto_bignum *crypto_ec_get_order(crypto_ec *e);

size_t crypto_ec_order_len(crypto_ec *e);

int crypto_ec_point_add(
    crypto_ec *e,
    const crypto_ec_point *a,
    const crypto_ec_point *b,
    crypto_ec_point *c);

crypto_bignum *crypto_ec_point_compute_y_sqr(
    crypto_ec *e,
    const crypto_bignum *x);

int crypto_ec_point_is_at_infinity(crypto_ec *e, const crypto_ec_point *p);

int crypto_ec_point_is_on_curve(crypto_ec *e, const crypto_ec_point *p);

int crypto_ec_point_cmp(
    const crypto_ec *e,
    const crypto_ec_point *a,
    const crypto_ec_point *b);

crypto_ec_point *crypto_ec_point_from_bin(crypto_ec *e, const u8 *val);

int crypto_ec_point_to_bin(
    crypto_ec *e,
    const crypto_ec_point *point,
    u8 *x,
    u8 *y);

void crypto_ec_deinit(crypto_ec *e);

int crypto_rand_bytes(void *buf, size_t len);

#endif
