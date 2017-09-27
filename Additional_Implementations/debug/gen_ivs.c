/*
 * Copyright (C) 2017 Nagravision S.A.
 */

#include "sign.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int genpk (uint8_t *pk, const uint8_t *sk);


/* sign CLI-provided message, default message otherwise */
int main (int ac, char **av) {
    uint8_t pk[PKLEN];
    uint8_t sk[SKLEN];
    uint8_t *m = NULL;
    int i;
    uint8_t *sm = NULL;
    unsigned long long mlen;
    unsigned long long smlen;
    int ret = 0;

#define CLEANUP                                                                \
    memset (sk, 0x00, SKLEN);                                                  \
    memset (pk, 0x00, PKLEN);                                                  \
    memset (sm, 0x00, mlen + SIGLEN);

#define SIGN                                                                   \
    if (crypto_sign (sm, &smlen, m, mlen, sk)) {                               \
        fprintf (stderr, "error: crypto_sign failed\n");                       \
        ret = 1;                                                               \
        goto label_exit_2;                                                     \
    }

#define VERIFY                                                                 \
    if (crypto_sign_open (m, &mlen, sm, smlen, pk)) {                          \
        fprintf (stderr, "error: crypto_sign_open failed\n");                  \
        ret = 1;                                                               \
        goto label_exit_2;                                                     \
    }

    if (ac == 2) {
        m = (uint8_t *)av[1];
        mlen = strlen (av[1]);
    } else {
        m = malloc (N);
        if (m == NULL) {
            ret = 1;
            goto label_exit_0;
        }
        for (i = 0; i < N; ++i) m[i] = i;
        mlen = N;
    }

    sm = malloc (mlen + SIGLEN);
    if (!sm) {
        ret = 1;
        goto label_exit_1;
    }

    memset (sk, 0x00, SKLEN);
    genpk (pk, sk);

    SIGN;
    VERIFY;
    CLEANUP;

    memset (sk, 0x01, SKLEN);
    genpk (pk, sk);

    SIGN;
    VERIFY;
    CLEANUP;

    memset (sk, 0xff, SKLEN);
    genpk (pk, sk);

    SIGN;
    VERIFY;


label_exit_2:
    free (sm);
label_exit_1:
    if (ac != 2) free (m);
label_exit_0:
    return ret;
}
