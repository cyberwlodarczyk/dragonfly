#include <stdio.h>
#include <stdlib.h>
#include <openssl/opensslv.h>
#include "shared.h"

#define RUNS 10000

static int exchange_test(int group, const u8 *pwd_a, const u8 *pwd_b)
{
    exchange *e = exchange_init(group);
    if (e == NULL)
    {
        return -1;
    }
    int ret = exchange_run(e, pwd_a, pwd_b);
    exchange_free(e);
    return ret;
}

static int exchange_test_correct(int group)
{
    u8 pwd[PWD_LEN];
    if (crypto_rand_bytes(pwd, PWD_LEN) != 0)
    {
        return -1;
    }
    return exchange_test(group, pwd, pwd);
}

static int exchange_test_incorrect(int group)
{
    u8 pwd_a[PWD_LEN];
    u8 pwd_b[PWD_LEN];
    if (crypto_rand_bytes(pwd_a, PWD_LEN) != 0 ||
        crypto_rand_bytes(pwd_b, PWD_LEN) != 0)
    {
        return -1;
    }
    return exchange_test(group, pwd_a, pwd_b) != 0 ? 0 : -1;
}

static int test_19_correct()
{
    return exchange_test_correct(19);
}

static int test_20_correct()
{
    return exchange_test_correct(20);
}

static int test_21_correct()
{
    return exchange_test_correct(21);
}

static int test_5_correct()
{
    return exchange_test_correct(5);
}

static int test_19_incorrect()
{
    return exchange_test_incorrect(19);
}

static int test_20_incorrect()
{
    return exchange_test_incorrect(20);
}

static int test_21_incorrect()
{
    return exchange_test_incorrect(21);
}

static int test_5_incorrect()
{
    return exchange_test_incorrect(5);
}

static int test_run(const char *name, int f())
{
    printf("%s: ", name);
    fflush(stdout);
    int fail = 0;
    for (int i = 0; i < RUNS; i++)
    {
        if (f() != 0)
        {
            fail++;
        }
    }
    if (fail == 0)
    {
        printf("ok\n");
        return 0;
    }
    else
    {
        printf("fail (%d/%d)\n", RUNS - fail, RUNS);
        return -1;
    }
}

int main()
{
    printf("%s\n", OPENSSL_VERSION_TEXT);
    printf("N = %d\n", RUNS);
    int ok = 1;
    ok = test_run("p_256_correct", test_19_correct) == 0 && ok;
    ok = test_run("p_256_incorrect", test_19_incorrect) == 0 && ok;
    ok = test_run("p_384_correct", test_20_correct) == 0 && ok;
    ok = test_run("p_384_incorrect", test_20_incorrect) == 0 && ok;
    ok = test_run("p_512_correct", test_21_correct) == 0 && ok;
    ok = test_run("p_512_incorrect", test_21_incorrect) == 0 && ok;
    ok = test_run("modp_1536_correct", test_5_correct) == 0 && ok;
    ok = test_run("modp_1536_incorrect", test_5_incorrect) == 0 && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
