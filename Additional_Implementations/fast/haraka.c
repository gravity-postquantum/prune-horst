/*
The MIT License (MIT)

Copyright (c) 2016 kste
original Haraka implementations

Copyright (c) 2017 Nagravision S.A.
changes by JP Aumasson, Guillaume Endignoux, 2017: improvements, non-ni versions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include "haraka.h"
#include <string.h>
#include <wmmintrin.h>

void haraka256 (unsigned char *out, const unsigned char *in) {
    __m128i s[2], tmp;

    s[0] = LOAD (in);
    s[1] = LOAD (in + 16);

    AES2 (s[0], s[1], 0);
    MIX2 (s[0], s[1]);

    AES2 (s[0], s[1], 4);
    MIX2 (s[0], s[1]);

    AES2 (s[0], s[1], 8);
    MIX2 (s[0], s[1]);

    AES2 (s[0], s[1], 12);
    MIX2 (s[0], s[1]);

    AES2 (s[0], s[1], 16);
    MIX2 (s[0], s[1]);

    AES2 (s[0], s[1], 20);
    MIX2 (s[0], s[1]);

    s[0] = _mm_xor_si128 (s[0], LOAD (in));
    s[1] = _mm_xor_si128 (s[1], LOAD (in + 16));

    STORE (out, s[0]);
    STORE (out + 16, s[1]);
}

void haraka256_4x (unsigned char *out, const unsigned char *in) {
    __m128i s[4][2], tmp;

    s[0][0] = LOAD (in);
    s[0][1] = LOAD (in + 16);
    s[1][0] = LOAD (in + 32);
    s[1][1] = LOAD (in + 48);
    s[2][0] = LOAD (in + 64);
    s[2][1] = LOAD (in + 80);
    s[3][0] = LOAD (in + 96);
    s[3][1] = LOAD (in + 112);

    AES2_4x (s[0], s[1], s[2], s[3], 0);
    MIX2 (s[0][0], s[0][1]);
    MIX2 (s[1][0], s[1][1]);
    MIX2 (s[2][0], s[2][1]);
    MIX2 (s[3][0], s[3][1]);

    AES2_4x (s[0], s[1], s[2], s[3], 4);
    MIX2 (s[0][0], s[0][1]);
    MIX2 (s[1][0], s[1][1]);
    MIX2 (s[2][0], s[2][1]);
    MIX2 (s[3][0], s[3][1]);

    AES2_4x (s[0], s[1], s[2], s[3], 8);
    MIX2 (s[0][0], s[0][1]);
    MIX2 (s[1][0], s[1][1]);
    MIX2 (s[2][0], s[2][1]);
    MIX2 (s[3][0], s[3][1]);

    AES2_4x (s[0], s[1], s[2], s[3], 12);
    MIX2 (s[0][0], s[0][1]);
    MIX2 (s[1][0], s[1][1]);
    MIX2 (s[2][0], s[2][1]);
    MIX2 (s[3][0], s[3][1]);

    AES2_4x (s[0], s[1], s[2], s[3], 16);
    MIX2 (s[0][0], s[0][1]);
    MIX2 (s[1][0], s[1][1]);
    MIX2 (s[2][0], s[2][1]);
    MIX2 (s[3][0], s[3][1]);

    AES2_4x (s[0], s[1], s[2], s[3], 20);
    MIX2 (s[0][0], s[0][1]);
    MIX2 (s[1][0], s[1][1]);
    MIX2 (s[2][0], s[2][1]);
    MIX2 (s[3][0], s[3][1]);

    s[0][0] = _mm_xor_si128 (s[0][0], LOAD (in));
    s[0][1] = _mm_xor_si128 (s[0][1], LOAD (in + 16));
    s[1][0] = _mm_xor_si128 (s[1][0], LOAD (in + 32));
    s[1][1] = _mm_xor_si128 (s[1][1], LOAD (in + 48));
    s[2][0] = _mm_xor_si128 (s[2][0], LOAD (in + 64));
    s[2][1] = _mm_xor_si128 (s[2][1], LOAD (in + 80));
    s[3][0] = _mm_xor_si128 (s[3][0], LOAD (in + 96));
    s[3][1] = _mm_xor_si128 (s[3][1], LOAD (in + 112));

    STORE (out, s[0][0]);
    STORE (out + 16, s[0][1]);
    STORE (out + 32, s[1][0]);
    STORE (out + 48, s[1][1]);
    STORE (out + 64, s[2][0]);
    STORE (out + 80, s[2][1]);
    STORE (out + 96, s[3][0]);
    STORE (out + 112, s[3][1]);
}

void haraka256_8x (unsigned char *out, const unsigned char *in) {
    haraka256_4x (out, in);
    haraka256_4x (out + 128, in + 128);
}

void haraka512 (unsigned char *out, const unsigned char *in) {
    __m128i s[4], tmp;

    s[0] = LOAD (in);
    s[1] = LOAD (in + 16);
    s[2] = LOAD (in + 32);
    s[3] = LOAD (in + 48);

    AES4 (s[0], s[1], s[2], s[3], 0);
    MIX4 (s[0], s[1], s[2], s[3]);

    AES4 (s[0], s[1], s[2], s[3], 8);
    MIX4 (s[0], s[1], s[2], s[3]);

    AES4 (s[0], s[1], s[2], s[3], 16);
    MIX4 (s[0], s[1], s[2], s[3]);

    AES4 (s[0], s[1], s[2], s[3], 24);
    MIX4 (s[0], s[1], s[2], s[3]);

    AES4 (s[0], s[1], s[2], s[3], 32);
    MIX4 (s[0], s[1], s[2], s[3]);

    AES4 (s[0], s[1], s[2], s[3], 40);
    MIX4 (s[0], s[1], s[2], s[3]);

    s[0] = _mm_xor_si128 (s[0], LOAD (in));
    s[1] = _mm_xor_si128 (s[1], LOAD (in + 16));
    s[2] = _mm_xor_si128 (s[2], LOAD (in + 32));
    s[3] = _mm_xor_si128 (s[3], LOAD (in + 48));

    _mm_storel_epi64 ((__m128i *)(out + 0),
                      _mm_shuffle_epi32 (s[0], _MM_SHUFFLE (3, 2, 3, 2)));
    _mm_storel_epi64 ((__m128i *)(out + 8),
                      _mm_shuffle_epi32 (s[1], _MM_SHUFFLE (3, 2, 3, 2)));
    _mm_storel_epi64 ((__m128i *)(out + 16), s[2]);
    _mm_storel_epi64 ((__m128i *)(out + 24), s[3]);
}

void haraka512_4x (unsigned char *out, const unsigned char *in) {
    __m128i s[4][4], tmp;
    int i, offset;

    s[0][0] = LOAD (in);
    s[0][1] = LOAD (in + 16);
    s[0][2] = LOAD (in + 32);
    s[0][3] = LOAD (in + 48);
    s[1][0] = LOAD (in + 64);
    s[1][1] = LOAD (in + 80);
    s[1][2] = LOAD (in + 96);
    s[1][3] = LOAD (in + 112);
    s[2][0] = LOAD (in + 128);
    s[2][1] = LOAD (in + 144);
    s[2][2] = LOAD (in + 160);
    s[2][3] = LOAD (in + 176);
    s[3][0] = LOAD (in + 192);
    s[3][1] = LOAD (in + 208);
    s[3][2] = LOAD (in + 224);
    s[3][3] = LOAD (in + 240);

    AES4_4x (s[0], s[1], s[2], s[3], 0);
    MIX4 (s[0][0], s[0][1], s[0][2], s[0][3]);
    MIX4 (s[1][0], s[1][1], s[1][2], s[1][3]);
    MIX4 (s[2][0], s[2][1], s[2][2], s[2][3]);
    MIX4 (s[3][0], s[3][1], s[3][2], s[3][3]);

    AES4_4x (s[0], s[1], s[2], s[3], 8);
    MIX4 (s[0][0], s[0][1], s[0][2], s[0][3]);
    MIX4 (s[1][0], s[1][1], s[1][2], s[1][3]);
    MIX4 (s[2][0], s[2][1], s[2][2], s[2][3]);
    MIX4 (s[3][0], s[3][1], s[3][2], s[3][3]);

    AES4_4x (s[0], s[1], s[2], s[3], 16);
    MIX4 (s[0][0], s[0][1], s[0][2], s[0][3]);
    MIX4 (s[1][0], s[1][1], s[1][2], s[1][3]);
    MIX4 (s[2][0], s[2][1], s[2][2], s[2][3]);
    MIX4 (s[3][0], s[3][1], s[3][2], s[3][3]);

    AES4_4x (s[0], s[1], s[2], s[3], 24);
    MIX4 (s[0][0], s[0][1], s[0][2], s[0][3]);
    MIX4 (s[1][0], s[1][1], s[1][2], s[1][3]);
    MIX4 (s[2][0], s[2][1], s[2][2], s[2][3]);
    MIX4 (s[3][0], s[3][1], s[3][2], s[3][3]);

    AES4_4x (s[0], s[1], s[2], s[3], 32);
    MIX4 (s[0][0], s[0][1], s[0][2], s[0][3]);
    MIX4 (s[1][0], s[1][1], s[1][2], s[1][3]);
    MIX4 (s[2][0], s[2][1], s[2][2], s[2][3]);
    MIX4 (s[3][0], s[3][1], s[3][2], s[3][3]);

    AES4_4x (s[0], s[1], s[2], s[3], 40);
    MIX4 (s[0][0], s[0][1], s[0][2], s[0][3]);
    MIX4 (s[1][0], s[1][1], s[1][2], s[1][3]);
    MIX4 (s[2][0], s[2][1], s[2][2], s[2][3]);
    MIX4 (s[3][0], s[3][1], s[3][2], s[3][3]);

    s[0][0] = _mm_xor_si128 (s[0][0], LOAD (in));
    s[0][1] = _mm_xor_si128 (s[0][1], LOAD (in + 16));
    s[0][2] = _mm_xor_si128 (s[0][2], LOAD (in + 32));
    s[0][3] = _mm_xor_si128 (s[0][3], LOAD (in + 48));
    s[1][0] = _mm_xor_si128 (s[1][0], LOAD (in + 64));
    s[1][1] = _mm_xor_si128 (s[1][1], LOAD (in + 80));
    s[1][2] = _mm_xor_si128 (s[1][2], LOAD (in + 96));
    s[1][3] = _mm_xor_si128 (s[1][3], LOAD (in + 112));
    s[2][0] = _mm_xor_si128 (s[2][0], LOAD (in + 128));
    s[2][1] = _mm_xor_si128 (s[2][1], LOAD (in + 144));
    s[2][2] = _mm_xor_si128 (s[2][2], LOAD (in + 160));
    s[2][3] = _mm_xor_si128 (s[2][3], LOAD (in + 176));
    s[3][0] = _mm_xor_si128 (s[3][0], LOAD (in + 192));
    s[3][1] = _mm_xor_si128 (s[3][1], LOAD (in + 208));
    s[3][2] = _mm_xor_si128 (s[3][2], LOAD (in + 224));
    s[3][3] = _mm_xor_si128 (s[3][3], LOAD (in + 240));

    for (i = 0; i < 4; i++) {
        offset = i * 32;
        _mm_storel_epi64 ((__m128i *)(out + 0 + offset),
                          _mm_shuffle_epi32 (s[i][0], _MM_SHUFFLE (3, 2, 3, 2)));
        _mm_storel_epi64 ((__m128i *)(out + 8 + offset),
                          _mm_shuffle_epi32 (s[i][1], _MM_SHUFFLE (3, 2, 3, 2)));
        _mm_storel_epi64 ((__m128i *)(out + 16 + offset), s[i][2]);
        _mm_storel_epi64 ((__m128i *)(out + 24 + offset), s[i][3]);
    }
}

void haraka512_8x (unsigned char *out, const unsigned char *in) {
    haraka512_4x (out, in);
    haraka512_4x (out + 128, in + 256);
}
