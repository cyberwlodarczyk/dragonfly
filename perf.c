#define _POSIX_C_SOURCE 199309L
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/opensslv.h>
#include "shared.h"

#define WARMUP_RUNS 100
#define RUNS 10000

static uint64_t time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t perf_commit(int group)
{
    u8 other_id[ID_LEN];
    u8 pwd[PWD_LEN];
    if (crypto_rand_bytes(other_id, ID_LEN) != 0 ||
        crypto_rand_bytes(pwd, PWD_LEN) != 0)
    {
        return 0;
    }
    peer *p = peer_init(group);
    if (p == NULL)
    {
        return 0;
    }
    uint64_t start = time_ns();
    if (peer_commit(p, other_id, pwd) != 0)
    {
        peer_free(p);
        return 0;
    }
    uint64_t diff = time_ns() - start;
    peer_free(p);
    return diff;
}

static uint64_t perf_19_commit()
{
    return perf_commit(19);
}

static uint64_t perf_20_commit()
{
    return perf_commit(20);
}

static uint64_t perf_21_commit()
{
    return perf_commit(21);
}

static uint64_t perf_5_commit()
{
    return perf_commit(5);
}

static uint64_t perf_process_commit(int group)
{
    u8 pwd[PWD_LEN];
    if (crypto_rand_bytes(pwd, PWD_LEN) != 0)
    {
        return 0;
    }
    exchange *e = exchange_init(group);
    if (e == NULL)
    {
        return 0;
    }
    peer *a = e->a;
    peer *b = e->b;
    if (peer_commit(a, b->id, pwd) != 0 ||
        peer_commit(b, a->id, pwd) != 0)
    {
        exchange_free(e);
        return 0;
    }
    uint64_t start = time_ns();
    if (peer_process_commit(a, b->commit) != 0)
    {
        exchange_free(e);
        return 0;
    }
    uint64_t diff = time_ns() - start;
    exchange_free(e);
    return diff;
}

static uint64_t perf_19_process_commit()
{
    return perf_process_commit(19);
}

static uint64_t perf_20_process_commit()
{
    return perf_process_commit(20);
}

static uint64_t perf_21_process_commit()
{
    return perf_process_commit(21);
}

static uint64_t perf_5_process_commit()
{
    return perf_process_commit(5);
}

static uint64_t perf_confirm(int group)
{
    u8 pwd[PWD_LEN];
    if (crypto_rand_bytes(pwd, PWD_LEN) != 0)
    {
        return 0;
    }
    exchange *e = exchange_init(group);
    if (e == NULL)
    {
        return 0;
    }
    peer *a = e->a;
    peer *b = e->b;
    if (peer_commit(a, b->id, pwd) != 0 ||
        peer_commit(b, a->id, pwd) != 0 ||
        peer_process_commit(a, b->commit) != 0 ||
        peer_process_commit(b, a->commit) != 0)
    {
        exchange_free(e);
        return 0;
    }
    uint64_t start = time_ns();
    if (peer_confirm(a) != 0)
    {
        exchange_free(e);
        return 0;
    }
    uint64_t diff = time_ns() - start;
    exchange_free(e);
    return diff;
}

static uint64_t perf_19_confirm()
{
    return perf_confirm(19);
}

static uint64_t perf_20_confirm()
{
    return perf_confirm(20);
}

static uint64_t perf_21_confirm()
{
    return perf_confirm(21);
}

static uint64_t perf_5_confirm()
{
    return perf_confirm(5);
}

static uint64_t perf_check_confirm(int group)
{
    u8 pwd[PWD_LEN];
    if (crypto_rand_bytes(pwd, PWD_LEN) != 0)
    {
        return 0;
    }
    exchange *e = exchange_init(group);
    if (e == NULL)
    {
        return 0;
    }
    peer *a = e->a;
    peer *b = e->b;
    if (peer_commit(a, b->id, pwd) != 0 ||
        peer_commit(b, a->id, pwd) != 0 ||
        peer_process_commit(a, b->commit) != 0 ||
        peer_process_commit(b, a->commit) != 0 ||
        peer_confirm(a) != 0 ||
        peer_confirm(b) != 0)
    {
        exchange_free(e);
        return 0;
    }
    uint64_t start = time_ns();
    if (peer_check_confirm(a, b->confirm) != 0)
    {
        exchange_free(e);
        return 0;
    }
    uint64_t diff = time_ns() - start;
    exchange_free(e);
    return diff;
}

static uint64_t perf_19_check_confirm()
{
    return perf_check_confirm(19);
}

static uint64_t perf_20_check_confirm()
{
    return perf_check_confirm(20);
}

static uint64_t perf_21_check_confirm()
{
    return perf_check_confirm(21);
}

static uint64_t perf_5_check_confirm()
{
    return perf_check_confirm(5);
}

static void perf_run(const char *name, uint64_t f())
{
    printf("%s: ", name);
    fflush(stdout);
    uint64_t total = 0;
    for (int i = 0; i < WARMUP_RUNS + RUNS; i++)
    {
        uint64_t ns = f();
        if (ns == 0)
        {
            printf("fail\n");
            return;
        }
        if (i >= WARMUP_RUNS)
        {
            total += ns;
        }
    }
    uint64_t avg = total / RUNS;
    printf("%.2fµs\n", (double)avg / 1000);
}

int main()
{
    printf("%s\n", OPENSSL_VERSION_TEXT);
    printf("N warmup = %d\n", WARMUP_RUNS);
    printf("N        = %d\n", RUNS);
    perf_run("p_256_commit", perf_19_commit);
    perf_run("p_256_process_commit", perf_19_process_commit);
    perf_run("p_256_confirm", perf_19_confirm);
    perf_run("p_256_check_confirm", perf_19_check_confirm);
    perf_run("p_384_commit", perf_20_commit);
    perf_run("p_384_process_commit", perf_20_process_commit);
    perf_run("p_384_confirm", perf_20_confirm);
    perf_run("p_384_check_confirm", perf_20_check_confirm);
    perf_run("p_512_commit", perf_21_commit);
    perf_run("p_512_process_commit", perf_21_process_commit);
    perf_run("p_512_confirm", perf_21_confirm);
    perf_run("p_512_check_confirm", perf_21_check_confirm);
    perf_run("modp_1536_commit", perf_5_commit);
    perf_run("modp_1536_process_commit", perf_5_process_commit);
    perf_run("modp_1536_confirm", perf_5_confirm);
    perf_run("modp_1536_check_confirm", perf_5_check_confirm);
    return EXIT_SUCCESS;
}
