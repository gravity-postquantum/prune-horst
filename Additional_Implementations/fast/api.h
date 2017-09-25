#pragma once

#ifndef CRYPTO_BYTES

#define CRYPTO_ALGNAME "PRUNE-HORST S"
#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 2048
#define CRYPTO_BYTES 20768

#if 0
#define CRYPTO_ALGNAME "PRUNE-HORST M"
#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 4096
#define CRYPTO_BYTES 23840
#endif

#if 0
#define CRYPTO_ALGNAME "PRUNE-HORST L"
#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 4096
#define CRYPTO_BYTES 26656
#endif

#endif

int crypto_sign_keypair (unsigned char *pk, unsigned char *sk);

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
