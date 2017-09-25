/*
 * Copyright (C) 2017 Nagravision S.A.
 */

#include "sign.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#if defined(__amd64__) || defined(__x86_64__)
static unsigned long long cpucycles (void) {
    unsigned long long result;
    __asm__ __volatile__(".byte 15;.byte 49\n"
                         "shlq $32,%%rdx\n"
                         "orq %%rdx,%%rax\n"
                         : "=a"(result)::"%rdx");
    return result;
}
#elif defined(__i386__)
static unsigned long long cpucycles (void) {
    unsigned long long result;
    __asm__ __volatile__(".byte 15;.byte 49;" : "=A"(result));
    return result;
}
#elif defined(_MSC_VER)
#include <intrin.h>
static unsigned long long cpucycles (void) { return __rdtsc (); }
#else
#error "Don't know how to count cycles on this platform!"
#endif

#define BENCH_WARMUP 64
#define BENCH_ROUNDS 32

static int bench_cmp (const void *x, const void *y) {
    const int64_t *ix = (const int64_t *)x;
    const int64_t *iy = (const int64_t *)y;
    return *ix - *iy;
}

extern void expandsk (uint8_t *ek, const uint8_t *sk);

int main () {

    int i;
    unsigned long long cycles[BENCH_ROUNDS + 1];
    unsigned long long smlen;
    unsigned long long mlen = N;
    uint8_t sk[SKLEN];
    uint8_t pk[PKLEN];
    uint8_t m[N];
    uint8_t *sm = malloc (N + SIGLEN);
    uint8_t *ek = malloc (EKLEN);
    uint8_t *sk2;
    struct timeval tm1, tm2;
    unsigned long long usecs;
    int ret = -1;

    if (!sm) {
        fprintf (stderr, "error: sm malloc failed\n");
        ret = 1;
        if (ek) free (ek);
        goto label_exit_0;
    }

    if (!ek) {
        fprintf (stderr, "error: ek malloc failed\n");
        ret = 1;
        goto label_exit_1;
    }

#define MEASURE(s)                                                                 \
    do {                                                                           \
        gettimeofday (&tm2, NULL);                                                 \
        usecs = 1000000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec); \
        for (i = 0; i < BENCH_ROUNDS; ++i)                                         \
            cycles[i] = cycles[i + 1] - cycles[i];                                 \
        qsort (cycles, BENCH_ROUNDS, sizeof (uint64_t), bench_cmp);                \
        printf ("\n# %s\n", s);                                                    \
        printf ("median cycles count:\t %6llu\n", cycles[BENCH_ROUNDS / 2]);       \
        printf ("average wall time:\t %.3f usec\n", (double)usecs / BENCH_ROUNDS); \
    } while (0)

    /***********************/
    /* crypto_sign_keypair */
    /***********************/

    for (i = 0; i < BENCH_WARMUP; ++i) {
        if (crypto_sign_keypair (pk, sk)) {
            fprintf (stderr, "error: crypto_sign_keypair failed in warmup\n");
            ret = 1;
            goto label_exit_2;
        }
        sk[0] = pk[0];
    }

    gettimeofday (&tm1, NULL);

    for (i = 0; i < BENCH_ROUNDS; ++i) {
        cycles[i] = cpucycles ();
        if (crypto_sign_keypair (pk, sk)) {
            fprintf (stderr,
                     "error: crypto_sign_keypair failed in benchmark\n");
            ret = 1;
            goto label_exit_2;
        }
        sk[0] = pk[0];
    }

    MEASURE ("crypto_sign_keypair");

    /***************/
    /* crypto_sign */
    /***************/

    if (crypto_sign_keypair (pk, sk)) {
        fprintf (stderr,
                 "error: crypto_sign_keypair failed before sign warmup\n");
        return 1;
    }

    for (i = 0; i < BENCH_WARMUP; ++i) {
        if (crypto_sign (sm, &smlen, m, mlen, sk)) {
            fprintf (stderr, "error: crypto_sign failed in warmup\n");
            ret = 1;
            goto label_exit_2;
        }
        m[0] = sm[0];
    }

    gettimeofday (&tm1, NULL);

    for (i = 0; i <= BENCH_ROUNDS; ++i) {
        cycles[i] = cpucycles ();
        if (crypto_sign (sm, &smlen, m, mlen, sk)) {
            fprintf (stderr, "error: crypto_sign failed in benchmark\n");
            ret = 1;
            goto label_exit_2;
        }
        m[0] = sm[0];
    }

    MEASURE ("crypto_sign");

    /**********************/
    /* crypto_sign_cached */
    /**********************/

    if (crypto_sign_keypair (pk, sk)) {
        fprintf (stderr, "error: crypto_sign_keypair failed before sign cached "
                         "warmup\n");
        ret = 1;
        goto label_exit_2;
    }
    expandsk (ek, sk);
    sk2 = sk + N;

    for (i = 0; i < BENCH_WARMUP; ++i) {
        if (crypto_sign_cached (sm, &smlen, m, mlen, sk2, ek)) {
            fprintf (stderr, "error: crypto_sign_cached failed in warmup\n");
            return 1;
            goto label_exit_2;
        }
        m[0] = sm[0];
    }

    gettimeofday (&tm1, NULL);

    for (i = 0; i <= BENCH_ROUNDS; ++i) {
        cycles[i] = cpucycles ();
        if (crypto_sign_cached (sm, &smlen, m, mlen, sk2, ek)) {
            fprintf (stderr, "error: crypto_sign_cached failed in benchmark\n");
            ret = 1;
            goto label_exit_2;
        }
        m[0] = sm[0];
    }

    MEASURE ("crypto_sign_cached");

    /********************/
    /* crypto_sign_open */
    /********************/

    if (crypto_sign_keypair (pk, sk)) {
        fprintf (stderr,
                 "error: crypto_sign_keypair failed before sign_open warmup\n");
        ret = 1;
        goto label_exit_2;
    }

    if (crypto_sign (sm, &smlen, m, mlen, sk)) {
        fprintf (stderr, "error: crypto_sign failed before sign_open warmup\n");
        ret = 1;
        goto label_exit_2;
    }

    for (i = 0; i < BENCH_WARMUP; ++i) {
        if (crypto_sign_open (m, &mlen, sm, smlen, pk)) {
            fprintf (stderr, "error: crypto_sign_open failed in warmup\n");
            ret = 1;
            goto label_exit_2;
        }
    }

    gettimeofday (&tm1, NULL);

    for (i = 0; i <= BENCH_ROUNDS; ++i) {
        cycles[i] = cpucycles ();
        if (crypto_sign_open (m, &mlen, sm, smlen, pk)) {
            fprintf (stderr, "error: crypto_sign_open failed in benchmark\n");
            ret = 1;
            goto label_exit_2;
        }
    }

    MEASURE ("crypto_sign_open");

    ret = 0;
label_exit_2:
    free (ek);
label_exit_1:
    free (sm);
label_exit_0:
    return ret;
}
