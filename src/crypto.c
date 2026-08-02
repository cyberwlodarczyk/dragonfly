#include "crypto.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include "const_time.h"

static int hmac_vector(
    char *digest,
    const u8 *key,
    size_t key_len,
    size_t num_elem,
    const u8 *addr[],
    const size_t *len,
    u8 *mac,
    unsigned int mdlen)
{
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (hmac == NULL)
    {
        return -1;
    }
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string("digest", digest, 0),
        OSSL_PARAM_construct_end()};
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
    EVP_MAC_free(hmac);
    if (ctx == NULL)
    {
        return -1;
    }
    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        goto fail;
    }
    for (size_t i = 0; i < num_elem; i++)
    {
        if (EVP_MAC_update(ctx, addr[i], len[i]) != 1)
        {
            goto fail;
        }
    }
    size_t mlen;
    int res = EVP_MAC_final(ctx, mac, &mlen, mdlen);
    EVP_MAC_CTX_free(ctx);
    return res == 1 ? 0 : -1;
fail:
    EVP_MAC_CTX_free(ctx);
    return -1;
}

int hmac_sha256_vector(
    const u8 *key,
    size_t key_len,
    size_t num_elem,
    const u8 *addr[],
    const size_t *len,
    u8 *mac)
{
    return hmac_vector("SHA256", key, key_len, num_elem, addr, len, mac, 32);
}

int hmac_sha256(
    const u8 *key,
    size_t key_len,
    const u8 *data,
    size_t data_len,
    u8 *mac)
{
    return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}

crypto_bignum *crypto_bignum_init(void)
{
    return BN_new();
}

crypto_bignum *crypto_bignum_init_set(const u8 *buf, size_t len)
{
    return BN_bin2bn(buf, (int)len, NULL);
}

crypto_bignum *crypto_bignum_init_uint(u32 val)
{
    BIGNUM *bn = BN_new();
    if (!bn)
    {
        return NULL;
    }
    if (BN_set_word(bn, val) != 1)
    {
        BN_free(bn);
        return NULL;
    }
    return bn;
}

int crypto_bignum_to_bin(
    const crypto_bignum *a,
    u8 *buf,
    size_t buflen,
    size_t padlen)
{
    if (padlen > buflen)
    {
        return -1;
    }
    if (padlen)
    {
        return BN_bn2binpad(a, buf, (int)padlen);
    }
    int num_bytes = BN_num_bytes(a);
    if ((size_t)num_bytes > buflen)
    {
        return -1;
    }
    int offset;
    if (padlen > (size_t)num_bytes)
    {
        offset = (int)padlen - num_bytes;
    }
    else
    {
        offset = 0;
    }
    os_memset(buf, 0, (size_t)offset);
    BN_bn2bin(a, buf + offset);
    return num_bytes + offset;
}

int crypto_bignum_rand(crypto_bignum *r, const crypto_bignum *m)
{
    return BN_rand_range(r, m) == 1 ? 0 : -1;
}

int crypto_bignum_rshift(
    const crypto_bignum *a,
    int n,
    crypto_bignum *r)
{
    return BN_rshift(r, a, n) == 1 ? 0 : -1;
}

int crypto_bignum_cmp(const crypto_bignum *a, const crypto_bignum *b)
{
    return BN_cmp(a, b);
}

int crypto_bignum_add(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c)
{
    return BN_add(c, a, b) ? 0 : -1;
}

int crypto_bignum_sub(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c)
{
    return BN_sub(c, a, b) ? 0 : -1;
}

int crypto_bignum_mod(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c)
{
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        return -1;
    }
    int res = BN_mod(c, a, b, bnctx);
    BN_CTX_free(bnctx);
    return res ? 0 : -1;
}

int crypto_bignum_mulmod(
    const crypto_bignum *a,
    const crypto_bignum *b,
    const crypto_bignum *c,
    crypto_bignum *d)
{
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        return -1;
    }
    int res = BN_mod_mul(d, a, b, c, bnctx);
    BN_CTX_free(bnctx);
    return res ? 0 : -1;
}

int crypto_bignum_exptmod(
    const crypto_bignum *a,
    const crypto_bignum *b,
    const crypto_bignum *c,
    crypto_bignum *d)
{
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        return -1;
    }
    int res = BN_mod_exp_mont_consttime(d, a, b, c, bnctx, NULL);
    BN_CTX_free(bnctx);
    return res ? 0 : -1;
}

int crypto_bignum_div(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c)
{
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        return -1;
    }
    int res = BN_div(c, NULL, a, b, bnctx);
    BN_CTX_free(bnctx);
    return res ? 0 : -1;
}

int crypto_bignum_inverse(
    const crypto_bignum *a,
    const crypto_bignum *b,
    crypto_bignum *c)
{
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        return -1;
    }
    BN_set_flags((crypto_bignum *)a, BN_FLG_CONSTTIME);
    BIGNUM *res = BN_mod_inverse(c, a, b, bnctx);
    BN_CTX_free(bnctx);
    return res ? 0 : -1;
}

int crypto_bignum_legendre(const crypto_bignum *a, const crypto_bignum *p)
{
    int res = -2;
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        return res;
    }
    BIGNUM *exp = BN_new();
    BIGNUM *tmp = BN_new();
    if (!exp || !tmp ||
        /* exp = (p-1) / 2 */
        !BN_sub(exp, p, BN_value_one()) ||
        !BN_rshift1(exp, exp) ||
        !BN_mod_exp_mont_consttime(tmp, a, exp, p, bnctx, NULL))
    {
        goto fail;
    }
    /* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need to use
     * constant time selection to avoid branches here. */
    res = -1;
    u32 mask = const_time_eq((u32)BN_is_word(tmp, 1), 1);
    res = const_time_select_int(mask, 1, res);
    mask = const_time_eq((u32)BN_is_zero(tmp), 1);
    res = const_time_select_int(mask, 0, res);
fail:
    BN_clear_free(tmp);
    BN_clear_free(exp);
    BN_CTX_free(bnctx);
    return res;
}

int crypto_bignum_is_zero(const crypto_bignum *a)
{
    return BN_is_zero(a);
}

int crypto_bignum_is_one(const crypto_bignum *a)
{
    return BN_is_one(a);
}

int crypto_bignum_is_odd(const crypto_bignum *a)
{
    return BN_is_odd(a);
}

void crypto_bignum_deinit(crypto_bignum *n, int clear)
{
    if (clear)
    {
        BN_clear_free((BIGNUM *)n);
    }
    else
    {
        BN_free((BIGNUM *)n);
    }
}

crypto_ec_point *crypto_ec_point_init(crypto_ec *e)
{
    if (e == NULL)
    {
        return NULL;
    }
    return EC_POINT_new(e->group);
}

int crypto_ec_point_mul(
    crypto_ec *e,
    const crypto_ec_point *p,
    const crypto_bignum *b,
    crypto_ec_point *res)
{
    return EC_POINT_mul(e->group, res, NULL, p, b, e->bnctx) ? 0 : -1;
}

int crypto_ec_point_invert(crypto_ec *e, crypto_ec_point *p)
{
    return EC_POINT_invert(e->group, p, e->bnctx) ? 0 : -1;
}

void crypto_ec_point_deinit(crypto_ec_point *p, int clear)
{
    if (clear)
    {
        EC_POINT_clear_free((EC_POINT *)p);
    }
    else
    {
        EC_POINT_free((EC_POINT *)p);
    }
}

static int crypto_ec_group_2_nid(int group)
{
    /* Map from IANA registry for IKE D-H groups to OpenSSL NID */
    switch (group)
    {
    case 19:
        return NID_X9_62_prime256v1;
    case 20:
        return NID_secp384r1;
    case 21:
        return NID_secp521r1;
    case 25:
        return NID_X9_62_prime192v1;
    case 26:
        return NID_secp224r1;
#ifdef NID_brainpoolP224r1
    case 27:
        return NID_brainpoolP224r1;
#endif /* NID_brainpoolP224r1 */
#ifdef NID_brainpoolP256r1
    case 28:
        return NID_brainpoolP256r1;
#endif /* NID_brainpoolP256r1 */
#ifdef NID_brainpoolP384r1
    case 29:
        return NID_brainpoolP384r1;
#endif /* NID_brainpoolP384r1 */
#ifdef NID_brainpoolP512r1
    case 30:
        return NID_brainpoolP512r1;
#endif /* NID_brainpoolP512r1 */
    default:
        return -1;
    }
}

crypto_ec *crypto_ec_init(int group)
{
    int nid = crypto_ec_group_2_nid(group);
    if (nid < 0)
    {
        return NULL;
    }
    crypto_ec *e = os_zalloc(sizeof(*e));
    if (e == NULL)
    {
        return NULL;
    }
    e->nid = nid;
    e->iana_group = group;
    e->bnctx = BN_CTX_new();
    e->group = EC_GROUP_new_by_curve_name(nid);
    e->prime = BN_new();
    e->order = BN_new();
    e->a = BN_new();
    e->b = BN_new();
    if (
        e->group == NULL ||
        e->bnctx == NULL ||
        e->prime == NULL ||
        e->order == NULL ||
        e->a == NULL ||
        e->b == NULL ||
        !EC_GROUP_get_curve(e->group, e->prime, e->a, e->b, e->bnctx) ||
        !EC_GROUP_get_order(e->group, e->order, e->bnctx))
    {
        crypto_ec_deinit(e);
        e = NULL;
    }
    return e;
}

const crypto_bignum *crypto_ec_get_prime(crypto_ec *e)
{
    return e->prime;
}

size_t crypto_ec_prime_len(crypto_ec *e)
{
    return (size_t)BN_num_bytes(e->prime);
}

size_t crypto_ec_prime_len_bits(crypto_ec *e)
{
    return (size_t)BN_num_bits(e->prime);
}

const crypto_bignum *crypto_ec_get_order(crypto_ec *e)
{
    return e->order;
}

size_t crypto_ec_order_len(crypto_ec *e)
{
    return (size_t)BN_num_bytes(e->order);
}

int crypto_ec_point_add(
    crypto_ec *e,
    const crypto_ec_point *a,
    const crypto_ec_point *b,
    crypto_ec_point *c)
{
    return EC_POINT_add(e->group, c, a, b, e->bnctx) ? 0 : -1;
}

crypto_bignum *crypto_ec_point_compute_y_sqr(
    crypto_ec *e,
    const crypto_bignum *x)
{
    BIGNUM *tmp = BN_new();
    /* y^2 = x^3 + ax + b = (x^2 + a)x + b */
    if (tmp &&
        BN_mod_sqr(tmp, x, e->prime, e->bnctx) &&
        BN_mod_add_quick(tmp, e->a, tmp, e->prime) &&
        BN_mod_mul(tmp, tmp, x, e->prime, e->bnctx) &&
        BN_mod_add_quick(tmp, tmp, e->b, e->prime))
    {
        return tmp;
    }
    BN_clear_free(tmp);
    return NULL;
}

int crypto_ec_point_is_at_infinity(crypto_ec *e, const crypto_ec_point *p)
{
    return EC_POINT_is_at_infinity(e->group, p);
}

int crypto_ec_point_is_on_curve(crypto_ec *e, const crypto_ec_point *p)
{
    return EC_POINT_is_on_curve(e->group, p, e->bnctx) == 1;
}

int crypto_ec_point_cmp(
    const crypto_ec *e,
    const crypto_ec_point *a,
    const crypto_ec_point *b)
{
    return EC_POINT_cmp(e->group, a, b, e->bnctx);
}

crypto_ec_point *crypto_ec_point_from_bin(crypto_ec *e, const u8 *val)
{
    int len = BN_num_bytes(e->prime);
    BIGNUM *x = BN_bin2bn(val, len, NULL);
    BIGNUM *y = BN_bin2bn(val + len, len, NULL);
    EC_POINT *elem = EC_POINT_new(e->group);
    if (x == NULL || y == NULL || elem == NULL)
    {
        BN_clear_free(x);
        BN_clear_free(y);
        EC_POINT_clear_free(elem);
        return NULL;
    }
    if (!EC_POINT_set_affine_coordinates(e->group, elem, x, y, e->bnctx))
    {
        EC_POINT_clear_free(elem);
        elem = NULL;
    }
    BN_clear_free(x);
    BN_clear_free(y);
    return elem;
}

int crypto_ec_point_to_bin(
    crypto_ec *e,
    const crypto_ec_point *point,
    u8 *x,
    u8 *y)
{
    int ret = -1;
    BIGNUM *x_bn = BN_new();
    BIGNUM *y_bn = BN_new();
    if (x_bn &&
        y_bn &&
        EC_POINT_get_affine_coordinates(
            e->group,
            point,
            x_bn,
            y_bn,
            e->bnctx))
    {
        size_t len = (size_t)BN_num_bytes(e->prime);
        if (x)
        {
            ret = crypto_bignum_to_bin(x_bn, x, len, len);
        }
        if (ret >= 0 && y)
        {
            ret = crypto_bignum_to_bin(y_bn, y, len, len);
        }
        if (ret > 0)
        {
            ret = 0;
        }
    }
    BN_clear_free(x_bn);
    BN_clear_free(y_bn);
    return ret;
}

void crypto_ec_deinit(crypto_ec *e)
{
    if (e == NULL)
    {
        return;
    }
    BN_clear_free(e->b);
    BN_clear_free(e->a);
    BN_clear_free(e->order);
    BN_clear_free(e->prime);
    EC_GROUP_free(e->group);
    BN_CTX_free(e->bnctx);
    os_free(e);
}

int crypto_rand_bytes(void *buf, size_t len)
{
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}
