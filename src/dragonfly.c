/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "dragonfly.h"

#include "sha256.h"
#include "const_time.h"

static void clear_temp_data(df_data *df)
{
    df_temporary_data *tmp;
    if (df == NULL || df->tmp == NULL)
    {
        return;
    }
    tmp = df->tmp;
    crypto_ec_deinit(tmp->ec);
    crypto_bignum_deinit(tmp->prime_buf, 0);
    crypto_bignum_deinit(tmp->order_buf, 0);
    crypto_bignum_deinit(tmp->rand, 1);
    crypto_bignum_deinit(tmp->pwe_ffc, 1);
    crypto_bignum_deinit(tmp->own_commit_scalar, 0);
    crypto_bignum_deinit(tmp->own_commit_element_ffc, 0);
    crypto_bignum_deinit(tmp->peer_commit_element_ffc, 0);
    crypto_ec_point_deinit(tmp->pwe_ecc, 1);
    crypto_ec_point_deinit(tmp->own_commit_element_ecc, 0);
    crypto_ec_point_deinit(tmp->peer_commit_element_ecc, 0);
    bin_clear_free(tmp, sizeof(*tmp));
    df->tmp = NULL;
}

static void clear_data(df_data *df)
{
    if (df == NULL)
    {
        return;
    }
    clear_temp_data(df);
    crypto_bignum_deinit(df->peer_commit_scalar, 0);
    os_memset(df, 0, sizeof(*df));
}

int dragonfly_set_group(df_data *df, int group)
{
    clear_data(df);
    df_temporary_data *tmp = df->tmp = os_zalloc(sizeof(*tmp));
    if (tmp == NULL)
    {
        return -1;
    }
    tmp->ec = crypto_ec_init(group);
    if (tmp->ec)
    {
        df->group = group;
        tmp->prime_len = crypto_ec_prime_len(tmp->ec);
        tmp->prime = crypto_ec_get_prime(tmp->ec);
        tmp->order_len = crypto_ec_order_len(tmp->ec);
        tmp->order = crypto_ec_get_order(tmp->ec);
        return 0;
    }
    tmp->dh = dh_groups_get(group);
    if (tmp->dh)
    {
        df->group = group;
        tmp->prime_len = tmp->dh->prime_len;
        if (tmp->prime_len > DF_MAX_PRIME_LEN)
        {
            clear_data(df);
            return -1;
        }
        tmp->prime_buf = crypto_bignum_init_set(
            tmp->dh->prime,
            tmp->prime_len);
        if (tmp->prime_buf == NULL)
        {
            clear_data(df);
            return -1;
        }
        tmp->prime = tmp->prime_buf;
        tmp->order_len = tmp->dh->order_len;
        tmp->order_buf = crypto_bignum_init_set(
            tmp->dh->order,
            tmp->dh->order_len);
        if (tmp->order_buf == NULL)
        {
            clear_data(df);
            return -1;
        }
        tmp->order = tmp->order_buf;
        return 0;
    }
    return -1;
}

static void pwd_seed_key(
    const u8 *aid,
    const u8 *bid,
    size_t id_len,
    u8 *key)
{
    if (os_memcmp(aid, bid, id_len) > 0)
    {
        os_memcpy(key, aid, id_len);
        os_memcpy(key + id_len, bid, id_len);
    }
    else
    {
        os_memcpy(key, bid, id_len);
        os_memcpy(key + id_len, aid, id_len);
    }
}

static crypto_bignum *get_rand_1_to_p_1(const crypto_bignum *prime)
{
    crypto_bignum *tmp = crypto_bignum_init();
    crypto_bignum *pm1 = crypto_bignum_init();
    crypto_bignum *one = crypto_bignum_init_set((const u8 *)"\x01", 1);
    if (
        !tmp ||
        !pm1 ||
        !one ||
        crypto_bignum_sub(prime, one, pm1) < 0 ||
        crypto_bignum_rand(tmp, pm1) < 0 ||
        crypto_bignum_add(tmp, one, tmp) < 0)
    {
        crypto_bignum_deinit(tmp, 0);
        tmp = NULL;
    }
    crypto_bignum_deinit(pm1, 0);
    crypto_bignum_deinit(one, 0);
    return tmp;
}

static int is_quadratic_residue_blind(
    crypto_ec *ec,
    const u8 *qr, const u8 *qnr,
    const crypto_bignum *val)
{
    int res = -1;
    crypto_bignum *qr_or_qnr = NULL;
    const crypto_bignum *prime = crypto_ec_get_prime(ec);
    size_t prime_len = crypto_ec_prime_len(ec);
    /*
     * Use a blinding technique to mask val while determining whether it is
     * a quadratic residue modulo p to avoid leaking timing information
     * while determining the Legendre symbol.
     *
     * v = val
     * r = a random number between 1 and p-1, inclusive
     * num = (v * r * r) modulo p
     */
    crypto_bignum *r = get_rand_1_to_p_1(prime);
    if (!r)
    {
        return -1;
    }
    crypto_bignum *num = crypto_bignum_init();
    if (!num ||
        crypto_bignum_mulmod(val, r, prime, num) < 0 ||
        crypto_bignum_mulmod(num, r, prime, num) < 0)
    {
        goto fail;
    }
    /*
     * Need to minimize differences in handling different cases, so try to
     * avoid branches and timing differences.
     *
     * If r is odd:
     * num = (num * qr) module p
     * LGR(num, p) = 1 ==> quadratic residue
     * else:
     * num = (num * qnr) module p
     * LGR(num, p) = -1 ==> quadratic residue
     *
     * mask is set to !odd(r)
     */
    u32 mask = const_time_is_zero((u32)crypto_bignum_is_odd(r));
    u8 qr_or_qnr_bin[DF_MAX_ECC_PRIME_LEN];
    const_time_select_bin((u8)mask, qnr, qr, prime_len, qr_or_qnr_bin);
    qr_or_qnr = crypto_bignum_init_set(
        qr_or_qnr_bin,
        prime_len);
    if (!qr_or_qnr ||
        crypto_bignum_mulmod(num, qr_or_qnr, prime, num) < 0)
    {
        goto fail;
    }
    /* branchless version of check = odd(r) ? 1 : -1, */
    int check = const_time_select_int(mask, -1, 1);
    /* Determine the Legendre symbol on the masked value */
    res = crypto_bignum_legendre(num, prime);
    if (res == -2)
    {
        res = -1;
        goto fail;
    }
    /* branchless version of res = res == check
     * (res is -1, 0, or 1; check is -1 or 1) */
    mask = const_time_eq((u32)res, (u32)check);
    res = const_time_select_int(mask, 1, 0);
fail:
    crypto_bignum_deinit(num, 1);
    crypto_bignum_deinit(r, 1);
    crypto_bignum_deinit(qr_or_qnr, 1);
    return res;
}

static int test_pwd_seed_ecc(
    df_data *df,
    const u8 *pwd_seed,
    const u8 *prime,
    const u8 *qr,
    const u8 *qnr,
    u8 *pwd_value)
{
    /* pwd-value = KDF-z(pwd-seed, "df Hunting and Pecking", p) */
    size_t bits = crypto_ec_prime_len_bits(df->tmp->ec);
    if (sha256_prf_bits(
            pwd_seed,
            SHA256_MAC_LEN,
            "df Hunting and Pecking",
            prime,
            df->tmp->prime_len,
            pwd_value,
            bits) < 0)
    {
        return -1;
    }
    if (bits % 8)
    {
        buf_shift_right(pwd_value, df->tmp->prime_len, 8 - bits % 8);
    }
    int cmp_prime = const_time_memcmp(
        pwd_value,
        prime,
        df->tmp->prime_len);
    /* Create a const_time mask for selection based on prf result
     * being smaller than prime. */
    u32 in_range = const_time_fill_msb((u32)cmp_prime);
    /* The algorithm description would skip the next steps if
     * cmp_prime >= 0 (return 0 here), but go through them regardless to
     * minimize externally observable differences in behavior. */
    crypto_bignum *x_cand = crypto_bignum_init_set(
        pwd_value,
        df->tmp->prime_len);
    if (!x_cand)
    {
        return -1;
    }
    crypto_bignum *y_sqr = crypto_ec_point_compute_y_sqr(df->tmp->ec, x_cand);
    crypto_bignum_deinit(x_cand, 1);
    if (!y_sqr)
    {
        return -1;
    }
    int res = is_quadratic_residue_blind(df->tmp->ec, qr, qnr, y_sqr);
    crypto_bignum_deinit(y_sqr, 1);
    if (res < 0)
    {
        return res;
    }
    return const_time_select_int(in_range, res, 0);
}

/* Returns -1 on fatal failure, 0 if PWE cannot be derived from the provided
 * pwd-seed, or 1 if a valid PWE was derived from pwd-seed. */
static int test_pwd_seed_ffc(
    df_data *df,
    const u8 *pwd_seed,
    crypto_bignum *pwe)
{
    u8 pwd_value[DF_MAX_PRIME_LEN];
    size_t bits = df->tmp->prime_len * 8;
    /* pwd-value = KDF-z(pwd-seed, "df Hunting and Pecking", p) */
    if (sha256_prf_bits(
            pwd_seed,
            SHA256_MAC_LEN,
            "df Hunting and Pecking",
            df->tmp->dh->prime,
            df->tmp->prime_len,
            pwd_value,
            bits) < 0)
    {
        return -1;
    }
    /* Check whether pwd-value < p */
    int res = const_time_memcmp(
        pwd_value,
        df->tmp->dh->prime,
        df->tmp->prime_len);
    /* pwd-value >= p is invalid, so res is < 0 for the valid cases and
     * the negative sign can be used to fill the mask for constant time
     * selection */
    u8 pwd_value_valid = (u8)const_time_fill_msb((u32)res);
    /* If pwd-value >= p, force pwd-value to be < p and perform the
     * calculations anyway to hide timing difference. The derived PWE will
     * be ignored in that case. */
    pwd_value[0] = const_time_select_u8(pwd_value_valid, pwd_value[0], 0);
    /* PWE = pwd-value^((p-1)/r) modulo p */
    res = -1;
    crypto_bignum *a = crypto_bignum_init_set(pwd_value, df->tmp->prime_len);
    crypto_bignum *b = NULL;
    if (!a)
    {
        goto fail;
    }
    u8 exp[1];
    /* This is an optimization based on the used group that does not depend
     * on the password in any way, so it is fine to use separate branches
     * for this step without constant time operations. */
    if (df->tmp->dh->safe_prime)
    {
        /*
         * r = (p-1)/2 for the group used here, so this becomes:
         * PWE = pwd-value^2 modulo p
         */
        exp[0] = 2;
        b = crypto_bignum_init_set(exp, sizeof(exp));
    }
    else
    {
        /* Calculate exponent: (p-1)/r */
        exp[0] = 1;
        b = crypto_bignum_init_set(exp, sizeof(exp));
        if (b == NULL ||
            crypto_bignum_sub(df->tmp->prime, b, b) < 0 ||
            crypto_bignum_div(b, df->tmp->order, b) < 0)
            goto fail;
    }
    if (!b)
    {
        goto fail;
    }
    res = crypto_bignum_exptmod(a, b, df->tmp->prime, pwe);
    if (res < 0)
    {
        goto fail;
    }
    /* There were no fatal errors in calculations, so determine the return
     * value using constant time operations. We get here for number of
     * invalid cases which are cleared here after having performed all the
     * computation. PWE is valid if pwd-value was less than prime and
     * PWE > 1. Start with pwd-value check first and then use constant time
     * operations to clear res to 0 if PWE is 0 or 1.
     */
    res = const_time_select_u8(pwd_value_valid, 1, 0);
    int is_val = crypto_bignum_is_zero(pwe);
    res = const_time_select_u8((u8)const_time_is_zero((u32)is_val), (u8)res, 0);
    is_val = crypto_bignum_is_one(pwe);
    res = const_time_select_u8((u8)const_time_is_zero((u32)is_val), (u8)res, 0);
fail:
    crypto_bignum_deinit(a, 1);
    crypto_bignum_deinit(b, 1);
    return res;
}

static int get_random_qr_qnr(
    const crypto_bignum *prime,
    crypto_bignum **qr,
    crypto_bignum **qnr)
{
    *qr = *qnr = NULL;
    while (!(*qr) || !(*qnr))
    {
        crypto_bignum *tmp = crypto_bignum_init();
        if (!tmp || crypto_bignum_rand(tmp, prime) < 0)
        {
            crypto_bignum_deinit(tmp, 0);
            break;
        }
        int res = crypto_bignum_legendre(tmp, prime);
        if (res == 1 && !(*qr))
        {
            *qr = tmp;
        }
        else if (res == -1 && !(*qnr))
        {
            *qnr = tmp;
        }
        else
        {
            crypto_bignum_deinit(tmp, 0);
            if (res == -2)
            {
                break;
            }
        }
    }
    if (*qr && *qnr)
    {
        return 0;
    }
    crypto_bignum_deinit(*qr, 0);
    crypto_bignum_deinit(*qnr, 0);
    *qr = *qnr = NULL;
    return -1;
}

static u8 min_pwe_loop_iter(int group)
{
    if (group == 22 || group == 23 || group == 24)
    {
        /* FFC groups for which pwd-value is likely to be >= p
         * frequently */
        return 40;
    }
    if (group == 1 || group == 2 || group == 5 || group == 14 ||
        group == 15 || group == 16 || group == 17 || group == 18)
    {
        /* FFC groups that have prime that is close to a power of two */
        return 1;
    }
    /* Default to 40 (this covers most ECC groups) */
    return 40;
}

/* res = sqrt(val) */
static int bignum_sqrt(crypto_ec *ec, const crypto_bignum *val, crypto_bignum *res)
{
    int ret = 0;
    /* For prime p such that p = 3 mod 4, sqrt(w) = w^((p+1)/4) mod p */
    const crypto_bignum *prime = crypto_ec_get_prime(ec);
    size_t prime_len = crypto_ec_prime_len(ec);
    crypto_bignum *tmp = crypto_bignum_init();
    crypto_bignum *one = crypto_bignum_init_uint(1);
    u8 prime_bin[DF_MAX_ECC_PRIME_LEN];
    if (
        crypto_bignum_to_bin(
            prime,
            prime_bin,
            sizeof(prime_bin),
            prime_len) < 0 ||
        (prime_bin[prime_len - 1] & 0x03) != 3 ||
        !tmp ||
        !one ||
        /* tmp = (p+1)/4 */
        crypto_bignum_add(prime, one, tmp) < 0 ||
        crypto_bignum_rshift(tmp, 2, tmp) < 0 ||
        /* res = sqrt(val) */
        crypto_bignum_exptmod(val, tmp, prime, res) < 0)
    {
        ret = -1;
    }
    crypto_bignum_deinit(tmp, 0);
    crypto_bignum_deinit(one, 0);
    return ret;
}

static int derive_pwe_ecc(
    df_data *df,
    const u8 *aid,
    const u8 *bid,
    const size_t id_len,
    const u8 *password,
    size_t password_len)
{
    u8 ids[2 * id_len];
    crypto_bignum *x = NULL, *y = NULL, *qr = NULL, *qnr = NULL;
    u8 x_bin[DF_MAX_ECC_PRIME_LEN];
    u8 x_cand_bin[DF_MAX_ECC_PRIME_LEN];
    u8 qr_bin[DF_MAX_ECC_PRIME_LEN];
    u8 qnr_bin[DF_MAX_ECC_PRIME_LEN];
    u8 x_y[2 * DF_MAX_ECC_PRIME_LEN];
    os_memset(x_bin, 0, sizeof(x_bin));
    int res = -1;
    u8 *stub_password = os_malloc(password_len);
    u8 *tmp_password = os_malloc(password_len);
    if (!stub_password ||
        !tmp_password ||
        crypto_rand_bytes(stub_password, password_len) < 0)
    {
        goto fail;
    }
    u8 prime[DF_MAX_ECC_PRIME_LEN];
    size_t prime_len = df->tmp->prime_len;
    if (crypto_bignum_to_bin(
            df->tmp->prime,
            prime,
            sizeof(prime),
            prime_len) < 0)
    {
        goto fail;
    }
    /*
     * Create a random quadratic residue (qr) and quadratic non-residue
     * (qnr) modulo p for blinding purposes during the loop.
     */
    if (get_random_qr_qnr(df->tmp->prime, &qr, &qnr) < 0 ||
        crypto_bignum_to_bin(qr, qr_bin, sizeof(qr_bin), prime_len) < 0 ||
        crypto_bignum_to_bin(qnr, qnr_bin, sizeof(qnr_bin), prime_len) < 0)
    {
        goto fail;
    }
    u8 counter;
    const u8 *addr[2];
    size_t len[2];
    /*
     * H(salt, ikm) = HMAC-SHA256(salt, ikm)
     * base = password
     * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
     *              base || counter)
     */
    pwd_seed_key(aid, bid, id_len, ids);
    addr[0] = tmp_password;
    len[0] = password_len;
    addr[1] = &counter;
    len[1] = sizeof(counter);
    /*
     * Continue for at least k iterations to protect against side-channel
     * attacks that attempt to determine the number of iterations required
     * in the loop.
     */
    u8 k = min_pwe_loop_iter(df->group);
    /* 0 (false) or 0xff (true) to be used as const_time_* mask */
    u8 found = 0;
    u8 pwd_seed_odd = 0;
    for (counter = 1; counter <= k || !found; counter++)
    {
        u8 pwd_seed[SHA256_MAC_LEN];
        if (counter > 200)
        {
            /* This should not happen in practice */
            break;
        }
        const_time_select_bin(
            found,
            stub_password,
            password,
            password_len,
            tmp_password);
        if (hmac_sha256_vector(
                ids,
                sizeof(ids), 2,
                addr,
                len,
                pwd_seed) < 0)
        {
            break;
        }
        res = test_pwd_seed_ecc(
            df,
            pwd_seed,
            prime,
            qr_bin,
            qnr_bin,
            x_cand_bin);
        const_time_select_bin(
            found,
            x_bin,
            x_cand_bin,
            prime_len,
            x_bin);
        pwd_seed_odd = const_time_select_u8(
            found,
            pwd_seed_odd,
            pwd_seed[SHA256_MAC_LEN - 1] & 0x01);
        os_memset(pwd_seed, 0, sizeof(pwd_seed));
        if (res < 0)
        {
            goto fail;
        }
        /* Need to minimize differences in handling res == 0 and 1 here
         * to avoid differences in timing and instruction cache access,
         * so use const_time_select_*() to make local copies of the
         * values based on whether this loop iteration was the one that
         * found the pwd-seed/x. */
        /* found is 0 or 0xff here and res is 0 or 1. Bitwise OR of them
         * (with res converted to 0/0xff) handles this in constant time.
         */
        found |= (u8)res * 0xff;
    }
    if (!found)
    {
        res = -1;
        goto fail;
    }
    x = crypto_bignum_init_set(x_bin, prime_len);
    if (!x)
    {
        res = -1;
        goto fail;
    }
    /* y = sqrt(x^3 + ax + b) mod p
     * if LSB(save) == LSB(y): PWE = (x, y)
     * else: PWE = (x, p - y)
     *
     * Calculate y and the two possible values for PWE and after that,
     * use constant time selection to copy the correct alternative.
     */
    y = crypto_ec_point_compute_y_sqr(df->tmp->ec, x);
    if (!y ||
        bignum_sqrt(df->tmp->ec, y, y) < 0 ||
        crypto_bignum_to_bin(y, x_y, DF_MAX_ECC_PRIME_LEN, prime_len) < 0 ||
        crypto_bignum_sub(df->tmp->prime, y, y) < 0 ||
        crypto_bignum_to_bin(
            y,
            x_y + DF_MAX_ECC_PRIME_LEN,
            DF_MAX_ECC_PRIME_LEN,
            prime_len) < 0)
    {
        goto fail;
    }
    u32 is_eq = const_time_eq(pwd_seed_odd, x_y[prime_len - 1] & 0x01);
    const_time_select_bin(
        (u8)is_eq,
        x_y,
        x_y + DF_MAX_ECC_PRIME_LEN,
        prime_len,
        x_y + prime_len);
    os_memcpy(x_y, x_bin, prime_len);
    crypto_ec_point_deinit(df->tmp->pwe_ecc, 1);
    df->tmp->pwe_ecc = crypto_ec_point_from_bin(df->tmp->ec, x_y);
    if (!df->tmp->pwe_ecc)
    {
        res = -1;
    }
fail:
    forced_memzero(x_y, sizeof(x_y));
    crypto_bignum_deinit(qr, 0);
    crypto_bignum_deinit(qnr, 0);
    crypto_bignum_deinit(y, 1);
    os_free(stub_password);
    bin_clear_free(tmp_password, password_len);
    crypto_bignum_deinit(x, 1);
    os_memset(x_bin, 0, sizeof(x_bin));
    os_memset(x_cand_bin, 0, sizeof(x_cand_bin));
    return res;
}

static int derive_pwe_ffc(
    df_data *df,
    const u8 *aid,
    const u8 *bid,
    const size_t id_len,
    const u8 *password,
    size_t password_len)
{
    u8 ids[2 * id_len];
    crypto_bignum_deinit(df->tmp->pwe_ffc, 1);
    df->tmp->pwe_ffc = NULL;
    size_t prime_len = df->tmp->prime_len;
    /* Allocate a buffer to maintain selected and candidate PWE for constant
     * time selection. */
    u8 *pwe_buf = os_zalloc(prime_len * 2);
    crypto_bignum *pwe = crypto_bignum_init();
    if (!pwe_buf || !pwe)
    {
        goto fail;
    }
    u8 counter;
    const u8 *addr[2];
    size_t len[2];
    /*
     * H(salt, ikm) = HMAC-SHA256(salt, ikm)
     * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
     *              password || counter)
     */
    pwd_seed_key(aid, bid, id_len, ids);
    addr[0] = password;
    len[0] = password_len;
    addr[1] = &counter;
    len[1] = sizeof(counter);
    u8 k = min_pwe_loop_iter(df->group);
    /* 0 (false) or 0xff (true) to be used as const_time_* mask */
    u8 found = 0;
    u8 sel_counter = 0;
    for (counter = 1; counter <= k || !found; counter++)
    {
        u8 pwd_seed[SHA256_MAC_LEN];
        if (counter > 200)
        {
            /* This should not happen in practice */
            break;
        }
        if (hmac_sha256_vector(
                ids,
                sizeof(ids),
                2,
                addr,
                len,
                pwd_seed) < 0)
        {
            break;
        }
        int res = test_pwd_seed_ffc(df, pwd_seed, pwe);
        /* res is -1 for fatal failure, 0 if a valid PWE was not found,
         * or 1 if a valid PWE was found. */
        if (res < 0)
        {
            break;
        }
        /* Store the candidate PWE into the second half of pwe_buf and
         * the selected PWE in the beginning of pwe_buf using constant
         * time selection. */
        if (crypto_bignum_to_bin(
                pwe,
                pwe_buf + prime_len,
                prime_len,
                prime_len) < 0)
        {
            break;
        }
        const_time_select_bin(
            found,
            pwe_buf,
            pwe_buf + prime_len,
            prime_len,
            pwe_buf);
        sel_counter = const_time_select_u8(found, sel_counter, counter);
        u8 mask = const_time_eq_u8((u32)res, 1);
        found = const_time_select_u8(found, found, mask);
    }
    if (!found)
    {
        goto fail;
    }
    df->tmp->pwe_ffc = crypto_bignum_init_set(pwe_buf, prime_len);
fail:
    crypto_bignum_deinit(pwe, 1);
    bin_clear_free(pwe_buf, prime_len * 2);
    return df->tmp->pwe_ffc ? 0 : -1;
}

static int derive_commit_element_ecc(df_data *df, crypto_bignum *mask)
{
    /* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
    if (!df->tmp->own_commit_element_ecc)
    {
        df->tmp->own_commit_element_ecc = crypto_ec_point_init(df->tmp->ec);
        if (!df->tmp->own_commit_element_ecc)
        {
            return -1;
        }
    }
    if (crypto_ec_point_mul(
            df->tmp->ec,
            df->tmp->pwe_ecc,
            mask,
            df->tmp->own_commit_element_ecc) < 0 ||
        crypto_ec_point_invert(
            df->tmp->ec,
            df->tmp->own_commit_element_ecc) < 0)
    {
        return -1;
    }
    return 0;
}

static int derive_commit_element_ffc(df_data *df, crypto_bignum *mask)
{
    /* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
    if (!df->tmp->own_commit_element_ffc)
    {
        df->tmp->own_commit_element_ffc = crypto_bignum_init();
        if (!df->tmp->own_commit_element_ffc)
        {
            return -1;
        }
    }
    if (crypto_bignum_exptmod(
            df->tmp->pwe_ffc,
            mask,
            df->tmp->prime,
            df->tmp->own_commit_element_ffc) < 0 ||
        crypto_bignum_inverse(
            df->tmp->own_commit_element_ffc,
            df->tmp->prime,
            df->tmp->own_commit_element_ffc) < 0)
    {
        return -1;
    }
    return 0;
}

static int get_rand_2_to_r_1(
    crypto_bignum *val,
    const crypto_bignum *order)
{
    return crypto_bignum_rand(val, order) == 0 &&
           !crypto_bignum_is_zero(val) &&
           !crypto_bignum_is_one(val);
}

static int generate_scalar(
    const crypto_bignum *order,
    crypto_bignum *_rand,
    crypto_bignum *_mask,
    crypto_bignum *scalar)
{
    /* Select two random values rand,mask such that 1 < rand,mask < r and
     * rand + mask mod r > 1. */
    for (int count = 0; count < 100; count++)
    {
        if (get_rand_2_to_r_1(_rand, order) &&
            get_rand_2_to_r_1(_mask, order) &&
            crypto_bignum_add(_rand, _mask, scalar) == 0 &&
            crypto_bignum_mod(scalar, order, scalar) == 0 &&
            !crypto_bignum_is_zero(scalar) &&
            !crypto_bignum_is_one(scalar))
        {
            return 0;
        }
    }
    return -1;
}

static int derive_commit(df_data *df)
{
    crypto_bignum *mask = crypto_bignum_init();
    if (!df->tmp->rand)
    {
        df->tmp->rand = crypto_bignum_init();
    }
    if (!df->tmp->own_commit_scalar)
    {
        df->tmp->own_commit_scalar = crypto_bignum_init();
    }
    int ret = !mask ||
              !df->tmp->rand ||
              !df->tmp->own_commit_scalar ||
              generate_scalar(
                  df->tmp->order,
                  df->tmp->rand,
                  mask,
                  df->tmp->own_commit_scalar) < 0 ||
              (df->tmp->ec &&
               derive_commit_element_ecc(df, mask) < 0) ||
              (df->tmp->dh &&
               derive_commit_element_ffc(df, mask) < 0);
    crypto_bignum_deinit(mask, 1);
    return ret ? -1 : 0;
}

int dragonfly_commit(
    const u8 *aid,
    const u8 *bid,
    const size_t id_len,
    const u8 *password,
    size_t password_len,
    df_data *df,
    df_buf *buf)
{
    if (df->tmp == NULL ||
        (df->tmp->ec && derive_pwe_ecc(
                            df,
                            aid,
                            bid,
                            id_len,
                            password,
                            password_len) < 0) ||
        (df->tmp->dh && derive_pwe_ffc(
                            df,
                            aid,
                            bid,
                            id_len,
                            password,
                            password_len) < 0))
    {
        return -1;
    }
    if (derive_commit(df) < 0)
    {
        return -1;
    }
    u8 *pos = df_buf_put(buf, df->tmp->prime_len);
    if (crypto_bignum_to_bin(
            df->tmp->own_commit_scalar,
            pos,
            df->tmp->prime_len,
            df->tmp->prime_len) < 0)
    {
        return -1;
    }
    if (df->tmp->ec)
    {
        pos = df_buf_put(buf, 2 * df->tmp->prime_len);
        if (crypto_ec_point_to_bin(
                df->tmp->ec,
                df->tmp->own_commit_element_ecc,
                pos,
                pos + df->tmp->prime_len) < 0)
        {
            return -1;
        }
    }
    else
    {
        pos = df_buf_put(buf, df->tmp->prime_len);
        if (crypto_bignum_to_bin(
                df->tmp->own_commit_element_ffc,
                pos,
                df->tmp->prime_len,
                df->tmp->prime_len) < 0)
        {
            return -1;
        }
    }
    return 0;
}

static int derive_k_ecc(df_data *df, u8 *k)
{
    int ret = -1;
    crypto_ec_point *K = crypto_ec_point_init(df->tmp->ec);
    if (K == NULL)
    {
        goto fail;
    }
    /*
     * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
     *                                        PEER-COMMIT-ELEMENT)))
     * If K is identity element (point-at-infinity), reject
     * k = F(K) (= x coordinate)
     */
    if (crypto_ec_point_mul(
            df->tmp->ec,
            df->tmp->pwe_ecc,
            df->peer_commit_scalar,
            K) < 0 ||
        crypto_ec_point_add(
            df->tmp->ec,
            K,
            df->tmp->peer_commit_element_ecc,
            K) < 0 ||
        crypto_ec_point_mul(df->tmp->ec, K, df->tmp->rand, K) < 0 ||
        crypto_ec_point_is_at_infinity(df->tmp->ec, K) ||
        crypto_ec_point_to_bin(df->tmp->ec, K, k, NULL) < 0)
    {
        goto fail;
    }
    ret = 0;
fail:
    crypto_ec_point_deinit(K, 1);
    return ret;
}

static int derive_k_ffc(df_data *df, u8 *k)
{
    int ret = -1;
    crypto_bignum *K = crypto_bignum_init();
    if (K == NULL)
    {
        goto fail;
    }
    /*
     * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
     *                                        PEER-COMMIT-ELEMENT)))
     * If K is identity element (one), reject.
     * k = F(K) (= x coordinate)
     */
    if (crypto_bignum_exptmod(
            df->tmp->pwe_ffc,
            df->peer_commit_scalar,
            df->tmp->prime,
            K) < 0 ||
        crypto_bignum_mulmod(
            K,
            df->tmp->peer_commit_element_ffc,
            df->tmp->prime,
            K) < 0 ||
        crypto_bignum_exptmod(K, df->tmp->rand, df->tmp->prime, K) < 0 ||
        crypto_bignum_is_one(K) ||
        crypto_bignum_to_bin(K, k, DF_MAX_PRIME_LEN, df->tmp->prime_len) < 0)
    {
        goto fail;
    }
    ret = 0;
fail:
    crypto_bignum_deinit(K, 1);
    return ret;
}

static int hkdf_extract(
    size_t hash_len,
    const u8 *salt,
    size_t salt_len,
    size_t num_elem,
    const u8 *addr[],
    const size_t len[],
    u8 *prk)
{
    if (hash_len == 32)
    {
        return hmac_sha256_vector(
            salt,
            salt_len,
            num_elem,
            addr,
            len,
            prk);
    }
    return -1;
}

static int kdf_hash(
    size_t hash_len,
    const u8 *k,
    const char *label,
    const u8 *context,
    size_t context_len,
    u8 *out,
    size_t out_len)
{
    if (hash_len == 32)
    {
        return sha256_prf(
            k,
            hash_len,
            label,
            context,
            context_len,
            out,
            out_len);
    }
    return -1;
}

static int derive_keys(df_data *df, const u8 *k)
{
    int ret = -1;
    df_buf *rejected_groups = NULL;
    crypto_bignum *tmp = crypto_bignum_init();
    if (tmp == NULL)
    {
        goto fail;
    }
    size_t hash_len = SHA256_MAC_LEN, prime_len = df->tmp->prime_len;
    /* keyseed = H(salt, k)
     * KCK || PMK = KDF-Hash-Length(keyseed, "SAE KCK and PMK",
     *                      (commit-scalar + peer-commit-scalar) modulo r)
     * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
     *
     * When SAE-PK is used,
     * KCK || PMK || KEK = KDF-Hash-Length(keyseed, "SAE-PK keys", context)
     */
    const u8 *salt;
    size_t salt_len;
    u8 zero[DF_MAX_HASH_LEN];
    os_memset(zero, 0, hash_len);
    salt = zero;
    salt_len = hash_len;
    const u8 *addr[1] = {k};
    size_t len[1] = {prime_len};
    u8 keyseed[DF_MAX_HASH_LEN];
    if (hkdf_extract(hash_len, salt, salt_len, 1, addr, len, keyseed) < 0)
    {
        goto fail;
    }
    if (crypto_bignum_add(
            df->tmp->own_commit_scalar,
            df->peer_commit_scalar,
            tmp) < 0 ||
        crypto_bignum_mod(
            tmp,
            df->tmp->order,
            tmp) < 0)
    {
        goto fail;
    }
    u8 val[DF_MAX_PRIME_LEN];
    /* IEEE Std 802.11-2016 is not exactly clear on the encoding of the bit
     * string that is needed for KCK, PMK, and PMKID derivation, but it
     * seems to make most sense to encode the
     * (commit-scalar + peer-commit-scalar) mod r part as a bit string by
     * zero padding it from left to the length of the order (in full
     * octets). */
    if (crypto_bignum_to_bin(
            tmp,
            val,
            sizeof(val),
            df->tmp->order_len) < 0)
    {
        goto fail;
    }
    u8 keys[2 * DF_MAX_HASH_LEN + DF_PMK_LEN_MAX];
    size_t pmk_len = DF_PMK_LEN;
    if (kdf_hash(
            hash_len,
            keyseed,
            "SAE KCK and PMK",
            val,
            df->tmp->order_len,
            keys,
            hash_len + pmk_len) < 0)
    {
        goto fail;
    }
    forced_memzero(keyseed, sizeof(keyseed));
    os_memcpy(df->tmp->kck, keys, hash_len);
    df->tmp->kck_len = hash_len;
    os_memcpy(df->pmk, keys + hash_len, pmk_len);
    df->pmk_len = pmk_len;
    os_memcpy(df->pmkid, val, DF_PMKID_LEN);
    forced_memzero(keys, sizeof(keys));
    ret = 0;
fail:
    df_buf_free(rejected_groups);
    crypto_bignum_deinit(tmp, 0);
    return ret;
}

static u16 parse_commit_scalar(
    df_data *df,
    const u8 **pos,
    const u8 *end)
{
    if ((long int)df->tmp->prime_len > end - *pos)
    {
        return 1;
    }
    crypto_bignum *peer_scalar = crypto_bignum_init_set(
        *pos,
        df->tmp->prime_len);
    if (peer_scalar == NULL)
    {
        return 1;
    }
    /* 1 < scalar < r */
    if (crypto_bignum_is_zero(peer_scalar) ||
        crypto_bignum_is_one(peer_scalar) ||
        crypto_bignum_cmp(peer_scalar, df->tmp->order) >= 0)
    {
        crypto_bignum_deinit(peer_scalar, 0);
        return 1;
    }
    crypto_bignum_deinit(df->peer_commit_scalar, 0);
    df->peer_commit_scalar = peer_scalar;
    *pos += df->tmp->prime_len;
    return 0;
}

static u16 parse_commit_element_ecc(
    df_data *df,
    const u8 **pos,
    const u8 *end)
{
    u8 prime[DF_MAX_ECC_PRIME_LEN];
    if ((long int)(2 * df->tmp->prime_len) > end - *pos)
    {
        return 1;
    }
    if (crypto_bignum_to_bin(
            df->tmp->prime,
            prime,
            sizeof(prime),
            df->tmp->prime_len) < 0)
    {
        return 1;
    }
    /* element x and y coordinates < p */
    if (
        os_memcmp(*pos, prime, df->tmp->prime_len) >= 0 ||
        os_memcmp(*pos + df->tmp->prime_len, prime, df->tmp->prime_len) >= 0)
    {
        return 1;
    }
    crypto_ec_point_deinit(df->tmp->peer_commit_element_ecc, 0);
    df->tmp->peer_commit_element_ecc =
        crypto_ec_point_from_bin(df->tmp->ec, *pos);
    if (!df->tmp->peer_commit_element_ecc)
    {
        return 1;
    }
    if (!crypto_ec_point_is_on_curve(
            df->tmp->ec,
            df->tmp->peer_commit_element_ecc))
    {
        return 1;
    }
    *pos += 2 * df->tmp->prime_len;
    return 0;
}

static u16 parse_commit_element_ffc(
    df_data *df,
    const u8 **pos,
    const u8 *end)
{
    if ((long int)df->tmp->prime_len > end - *pos)
    {
        return 1;
    }
    crypto_bignum_deinit(df->tmp->peer_commit_element_ffc, 0);
    df->tmp->peer_commit_element_ffc =
        crypto_bignum_init_set(*pos, df->tmp->prime_len);
    if (df->tmp->peer_commit_element_ffc == NULL)
    {
        return 1;
    }
    /* 1 < element < p - 1 */
    crypto_bignum *res = crypto_bignum_init();
    const u8 one_bin[1] = {0x01};
    crypto_bignum *one = crypto_bignum_init_set(one_bin, sizeof(one_bin));
    if (!res ||
        !one ||
        crypto_bignum_sub(df->tmp->prime, one, res) ||
        crypto_bignum_is_zero(df->tmp->peer_commit_element_ffc) ||
        crypto_bignum_is_one(df->tmp->peer_commit_element_ffc) ||
        crypto_bignum_cmp(df->tmp->peer_commit_element_ffc, res) >= 0)
    {
        crypto_bignum_deinit(res, 0);
        crypto_bignum_deinit(one, 0);
        return 1;
    }
    crypto_bignum_deinit(one, 0);
    /* scalar-op(r, ELEMENT) = 1 modulo p */
    if (crypto_bignum_exptmod(
            df->tmp->peer_commit_element_ffc,
            df->tmp->order,
            df->tmp->prime,
            res) < 0 ||
        !crypto_bignum_is_one(res))
    {
        crypto_bignum_deinit(res, 0);
        return 1;
    }
    crypto_bignum_deinit(res, 0);
    *pos += df->tmp->prime_len;
    return 0;
}

static u16 parse_commit_element(
    df_data *df,
    const u8 **pos,
    const u8 *end)
{
    if (df->tmp->dh != NULL)
    {
        return parse_commit_element_ffc(df, pos, end);
    }
    return parse_commit_element_ecc(df, pos, end);
}

static u16 parse_commit(df_data *df, const u8 *data, size_t len)
{
    const u8 *pos = data, *end = data + len;
    /* Check Finite Cyclic Group */
    if (end - pos < 2)
    {
        return 1;
    }
    /* commit-scalar */
    u16 res = parse_commit_scalar(df, &pos, end);
    if (res != 0)
    {
        return res;
    }
    /* commit-element */
    res = parse_commit_element(df, &pos, end);
    if (res != 0)
    {
        return res;
    }
    /*
     * Check whether peer-commit-scalar and PEER-COMMIT-ELEMENT are same as
     * the values we sent which would be evidence of a reflection attack.
     */
    if (!df->tmp->own_commit_scalar ||
        crypto_bignum_cmp(
            df->tmp->own_commit_scalar,
            df->peer_commit_scalar) != 0 ||
        (df->tmp->dh &&
         (!df->tmp->own_commit_element_ffc ||
          crypto_bignum_cmp(
              df->tmp->own_commit_element_ffc,
              df->tmp->peer_commit_element_ffc) != 0)) ||
        (df->tmp->ec &&
         (!df->tmp->own_commit_element_ecc ||
          crypto_ec_point_cmp(
              df->tmp->ec,
              df->tmp->own_commit_element_ecc,
              df->tmp->peer_commit_element_ecc) != 0)))
    {
        return 0; /* scalars/elements are different */
    }
    /*
     * This is a reflection attack - return special value to trigger caller
     * to silently discard the frame instead of replying with a specific
     * status code.
     */
    return 65535;
}

int dragonfly_process_commit(df_data *df, const u8 *buf, size_t len)
{
    if (parse_commit(df, buf, len) != 0)
    {
        return -1;
    }
    u8 k[DF_MAX_PRIME_LEN];
    if (df->tmp == NULL ||
        (df->tmp->ec && derive_k_ecc(df, k) < 0) ||
        (df->tmp->dh && derive_k_ffc(df, k) < 0) ||
        derive_keys(df, k) < 0)
    {
        return -1;
    }
    return 0;
}

static int cn_confirm(
    df_data *df,
    const crypto_bignum *scalar1,
    const u8 *element1,
    size_t element1_len,
    const crypto_bignum *scalar2,
    const u8 *element2,
    size_t element2_len,
    u8 *confirm)
{
    u8 scalar_b1[DF_MAX_PRIME_LEN], scalar_b2[DF_MAX_PRIME_LEN];
    /* Confirm
     * CN(key, X, Y, Z, ...) =
     *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
     * confirm = CN(KCK, commit-scalar, COMMIT-ELEMENT,
     *              peer-commit-scalar, PEER-COMMIT-ELEMENT)
     * verifier = CN(KCK, peer-commit-scalar,
     *               PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
     */
    if (crypto_bignum_to_bin(
            scalar1,
            scalar_b1,
            sizeof(scalar_b1),
            df->tmp->prime_len) < 0 ||
        crypto_bignum_to_bin(
            scalar2,
            scalar_b2, sizeof(scalar_b2),
            df->tmp->prime_len) < 0)
    {
        return -1;
    }
    const u8 *addr[4];
    size_t len[4];
    addr[0] = scalar_b1;
    len[0] = df->tmp->prime_len;
    addr[1] = element1;
    len[1] = element1_len;
    addr[2] = scalar_b2;
    len[2] = df->tmp->prime_len;
    addr[3] = element2;
    len[3] = element2_len;
    return hkdf_extract(
        df->tmp->kck_len,
        df->tmp->kck,
        df->tmp->kck_len,
        4,
        addr,
        len,
        confirm);
}

static int cn_confirm_ecc(
    df_data *df,
    const crypto_bignum *scalar1,
    const crypto_ec_point *element1,
    const crypto_bignum *scalar2,
    const crypto_ec_point *element2,
    u8 *confirm)
{
    u8 element_b1[2 * DF_MAX_ECC_PRIME_LEN];
    u8 element_b2[2 * DF_MAX_ECC_PRIME_LEN];
    if (crypto_ec_point_to_bin(
            df->tmp->ec,
            element1,
            element_b1,
            element_b1 + df->tmp->prime_len) < 0 ||
        crypto_ec_point_to_bin(
            df->tmp->ec,
            element2,
            element_b2,
            element_b2 + df->tmp->prime_len) < 0 ||
        cn_confirm(
            df,
            scalar1,
            element_b1,
            2 * df->tmp->prime_len,
            scalar2,
            element_b2, 2 * df->tmp->prime_len,
            confirm) < 0)
    {
        return -1;
    }
    return 0;
}

static int cn_confirm_ffc(
    df_data *df,
    const crypto_bignum *scalar1,
    const crypto_bignum *element1,
    const crypto_bignum *scalar2,
    const crypto_bignum *element2,
    u8 *confirm)
{
    u8 element_b1[DF_MAX_PRIME_LEN];
    u8 element_b2[DF_MAX_PRIME_LEN];
    if (crypto_bignum_to_bin(
            element1,
            element_b1,
            sizeof(element_b1),
            df->tmp->prime_len) < 0 ||
        crypto_bignum_to_bin(
            element2,
            element_b2,
            sizeof(element_b2),
            df->tmp->prime_len) < 0 ||
        cn_confirm(
            df,
            scalar1,
            element_b1,
            df->tmp->prime_len,
            scalar2,
            element_b2,
            df->tmp->prime_len,
            confirm) < 0)
    {
        return -1;
    }
    return 0;
}

int dragonfly_confirm(df_data *df, df_buf *buf)
{
    if (df->tmp == NULL)
    {
        return -1;
    }
    int res;
    if (df->tmp->ec != NULL)
    {
        res = cn_confirm_ecc(
            df,
            df->tmp->own_commit_scalar,
            df->tmp->own_commit_element_ecc,
            df->peer_commit_scalar,
            df->tmp->peer_commit_element_ecc,
            df_buf_put(buf, df->tmp->kck_len));
    }
    else
    {
        res = cn_confirm_ffc(
            df,
            df->tmp->own_commit_scalar,
            df->tmp->own_commit_element_ffc,
            df->peer_commit_scalar,
            df->tmp->peer_commit_element_ffc,
            df_buf_put(buf, df->tmp->kck_len));
    }
    return res;
}

int dragonfly_check_confirm(df_data *df, const u8 *buf, size_t len)
{
    if (df->tmp == NULL)
    {
        return -1;
    }
    if (len < df->tmp->kck_len)
    {
        return -1;
    }
    if (!df->peer_commit_scalar || !df->tmp->own_commit_scalar)
    {
        return -1;
    }
    u8 verifier[DF_MAX_HASH_LEN];
    if (df->tmp->ec)
    {
        if (!df->tmp->peer_commit_element_ecc ||
            !df->tmp->own_commit_element_ecc ||
            cn_confirm_ecc(
                df,
                df->peer_commit_scalar,
                df->tmp->peer_commit_element_ecc,
                df->tmp->own_commit_scalar,
                df->tmp->own_commit_element_ecc,
                verifier) < 0)
        {
            return -1;
        }
    }
    else
    {
        if (!df->tmp->peer_commit_element_ffc ||
            !df->tmp->own_commit_element_ffc ||
            cn_confirm_ffc(
                df,
                df->peer_commit_scalar,
                df->tmp->peer_commit_element_ffc,
                df->tmp->own_commit_scalar,
                df->tmp->own_commit_element_ffc,
                verifier) < 0)
        {
            return -1;
        }
    }
    if (os_memcmp_const(verifier, buf, len) != 0)
    {
        return -1;
    }
    return 0;
}
