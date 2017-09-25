/*
 * Copyright (C) 2017 Nagravision S.A.
 */

#pragma once

#include <stdint.h>

/* values otherwise passed through CLI flags */
#if defined(SUPERCOP)
/* default version */
#define LOGT 17
#define K 54 /* K = subset size, number of keys revealed in a signature */
#define LOGC 6
#endif

#define N 32            /* byte length of hashes, shouldn't change */
#define T (1 << (LOGT)) /* T = set size, number of leaves in the tree */

#define PKLEN (N * (1 << LOGC)) /* pubkey byte length */
#define SKLEN (2 * N)           /* privkey byte length */
#define EKLEN (N * T)           /* subkeys total byte length */
#define SIGLEN ((K * N) + (K * (LOGT - LOGC) * N) + N)

#define SUBKEYS(s) ((s) + N)         /* offset of subkeys in a sig */
#define PATHS(s) ((s) + N + (K * N)) /* offset of auth paths in a sig */

#define DRBG_IVLEN 16 /* byte length of DRBG IV (here AES-CTR nonce) */

/* hashes as defined in the specs */
#define HASH32(dst, src) haraka256 (dst, src)
#define HASH64(dst, src) haraka512 (dst, src)
#define HASH(h, m, mlen) SHA256 (m, mlen, h)

#define PARALLELISM 4 /* can be changed to 4 or 8 */
#define HASH32x4(dst, src) haraka256_4x (dst, src)
#define HASH32x8(dst, src) haraka256_8x (dst, src)
#define HASH64x4(dst, src) haraka512_4x (dst, src)
#define HASH64x8(dst, src) haraka512_8x (dst, src)

/* DRBG used in subset generation */
#define DRBG(dst, k, iv, len) aesctr256 (dst, k, iv, len)

/* convenience macro for copying hashes */
#define HCPY(dst, src) memcpy (dst, src, N)

/* big-endian deserialization from/to 32-bit word */
#define U8TO32(p)                                                              \
    (((uint32_t) ((p)[3]) << 24) | ((uint32_t) ((p)[2]) << 16) |               \
     ((uint32_t) ((p)[1]) << 8) | ((uint32_t) ((p)[0])))

int crypto_sign_keypair (unsigned char *pk, unsigned char *sk);

int crypto_sign_cached (unsigned char *sm,
                        unsigned long long *smlen,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *sk2,
                        const unsigned char *ek);

int crypto_sign (unsigned char *sm,
                 unsigned long long *smlen,
                 const unsigned char *m,
                 unsigned long long mlen,
                 const unsigned char *sk);

int crypto_sign_open (unsigned char *m,
                      unsigned long long *mlen,
                      const unsigned char *sm,
                      unsigned long long smlen,
                      const unsigned char *pk);
