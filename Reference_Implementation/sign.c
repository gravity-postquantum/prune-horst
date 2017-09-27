/*
 * Copyright (C) 2017 Nagravision S.A.
 */

#include "sign.h"
#include "aes.h"
#include "haraka.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(SUPERCOP)
#include "randombytes.h"
#endif


static void getsubset (int *subset, const uint8_t *mhash, const uint8_t *seed) {
#define BYTES_PER_INDEX 4
#define STREAMLEN 8 * K /* count twice as many indexes as needed */
    uint8_t tohash[2 * N];
    uint8_t subset_seed[N];
    uint8_t iv[DRBG_IVLEN] = { 0 };
    uint8_t randstream[STREAMLEN];
    int index, duplicate, i, count = 0;
    size_t offset = 0;

    HCPY (tohash, seed);
    HCPY (tohash + N, mhash);
    HASH64 (subset_seed, tohash);
    DRBG (randstream, subset_seed, iv, STREAMLEN);

    while (count < K) {
        /* ok to take mod since T is a power of 2 */
        index = U8TO32 (randstream + offset) % T;
        offset += BYTES_PER_INDEX;
        duplicate = 0;
        for (i = 0; i < count; ++i)
            if (subset[i] == index) duplicate++;
        if (!duplicate) {
            subset[count] = index;
            count++;
        }
    }
}


void expandsk (uint8_t *ek, const uint8_t *sk) {
    uint8_t iv[DRBG_IVLEN] = { 0 };
    DRBG (ek, sk, iv, EKLEN);
}


int genpk (uint8_t *pk, const uint8_t *sk) {

    int i, j, l;
    int hashes = T;
    uint8_t *ek = NULL;

    ek = malloc (T * N);
    if (!ek) return 1;

    /* expand sk to T subkeys */
    expandsk (ek, sk);

    /* hash the T hashed subkeys */
    for (j = 0; j < T; ++j) HASH32 (ek + (j * N), ek + (j * N));

    /* compute the binary hash tree up to level LOGT - LOGC (root if LOGC=0) */
    for (l = 0; l < LOGT - LOGC; ++l) {
        /* halved number of hashes */
        hashes = hashes / 2;
        for (i = 0; i < hashes; ++i) HASH64 (ek + (i * N), ek + (2 * i * N));
    }

    memcpy (pk, ek, PKLEN);
    free (ek);
    return 0;
}


int crypto_sign_keypair (unsigned char *pk, unsigned char *sk) {
    randombytes (sk, SKLEN);
    return genpk (pk, sk);
}


int crypto_sign_cached (unsigned char *sm,
                        unsigned long long *smlen,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *sk2,
                        const unsigned char *ek) {
    int i, j, l, index, sibling, hashes;
    uint8_t mhash[N];
    int subset[K];
    uint8_t tohash[2 * N];
    uint8_t signature_seed[N];
    uint8_t *subkeys, *paths, *buf;

    /* sanity checks */
    if (!sm || !smlen || !m || !sk2 || !ek) return 1;

    /* hash the message with SHA-256 */
    HASH (mhash, m, mlen);

    /* compute a subset from the message hash and secret key */
    HCPY (tohash, sk2);
    HCPY (tohash + N, mhash);
    HASH64 (signature_seed, tohash);

    getsubset (subset, mhash, signature_seed);
    HCPY (sm + mlen, signature_seed);


    /* append subkeys from the subset to the signature */
    subkeys = SUBKEYS (sm + mlen);
    for (i = 0; i < K; ++i) {
        index = subset[i];
        HCPY (subkeys + (i * N), ek + (index * N));
    }

    /* buffer to store the tree's nodes */
    buf = malloc (T * N);
    if (!buf) return 1;
    /* pointer to the start of auth paths in the signature */
    paths = PATHS (sm + mlen);

    /* hash subkeys to get the tree's leaves */
    for (j = 0; j < T; ++j) HASH32 (buf + (j * N), ek + (j * N));

    /* compute the tree from the leaves, til level LOGC */
    hashes = T;
    for (l = 0; l < LOGT - LOGC; ++l) {
        /* append the sibling to the sig for each of the K subkeys */
        for (i = 0; i < K; ++i) {
            sibling = subset[i] ^ 1;
            HCPY (paths + (K * N * l) + (i * N), buf + sibling * N);
            subset[i] = subset[i] / 2;
        }
        hashes = hashes / 2;
        for (i = 0; i < hashes; ++i) HASH64 (buf + (i * N), buf + (2 * i * N));
    }

    memmove (sm, m, mlen);
    *smlen = mlen + SIGLEN;

    free (buf);
    return 0;
}


int crypto_sign (unsigned char *sm,
                 unsigned long long *smlen,
                 const unsigned char *m,
                 unsigned long long mlen,
                 const unsigned char *sk) {

    /* expand sk into T subkeys */
    uint8_t *ek = NULL;
    int ret = 1;
    if (!sk || !m) return 1;
    ek = malloc (EKLEN);
    if (!ek) return 1;
    expandsk (ek, sk);
    ret = crypto_sign_cached (sm, smlen, m, mlen, sk + N, ek);
    free (ek);
    return ret;
}


int crypto_sign_open (unsigned char *m,
                      unsigned long long *mlen,
                      const unsigned char *sm,
                      unsigned long long smlen,
                      const unsigned char *pk) {
    int i, l, index;
    uint8_t mhash[N];
    int subset[K];
    uint8_t tmp[N];
    uint8_t buf[N * 2];
    const uint8_t *subkeys = NULL;
    const uint8_t *paths = NULL;

    /* sanity checks */
    if (!sm || !m || !pk || smlen < SIGLEN) return 1;

    *mlen = smlen - SIGLEN;
    subkeys = SUBKEYS (sm + *mlen);
    paths = PATHS (sm + *mlen);

    /* hash the message with SHA-256 */
    HASH (mhash, sm, smlen - SIGLEN);

    /* compute a subset from the message hash and the subset seed */
    getsubset (subset, mhash, sm + *mlen);

    /* compute the tree's root for each of the K subset leaves, using nodes from
     * the auth path */
    for (i = 0; i < K; ++i) {
        index = subset[i];
        HASH32 (tmp, subkeys + (i * N));

        for (l = 0; l < LOGT - LOGC; ++l) {
            if (index % 2 == 0) {
                HCPY (buf, tmp);
                HCPY (buf + N, paths + (K * N * l) + (i * N));
            } else {
                HCPY (buf, paths + (K * N * l) + (i * N));
                HCPY (buf + N, tmp);
            }

            HASH64 (tmp, buf);
            index = index / 2;
        }

        /* check that the root matches the node stored in the pubkey */
        if (!memcmp (pk + (index * N), tmp, N)) continue;
        return 1; /* fail if failed to verify root */
    }

    memmove (m, sm, smlen - SIGLEN);
    return 0;
}
