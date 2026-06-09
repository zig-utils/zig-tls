#pragma once

#include <stdint.h>
#include <string.h>

typedef uintptr_t br_word_t;
typedef intptr_t br_signed_t;

#define BR_WORD_MAX UINT64_MAX

static inline br_word_t br_full_add(br_word_t x, br_word_t y, br_word_t carry, br_word_t *sum) {
    unsigned __int128 wide = (unsigned __int128)x + y + carry;
    *sum = (br_word_t)wide;
    return (br_word_t)(wide >> 64);
}

static inline br_word_t br_full_sub(br_word_t x, br_word_t y, br_word_t borrow, br_word_t *diff) {
    unsigned __int128 subtrahend = (unsigned __int128)y + borrow;
    *diff = (br_word_t)((unsigned __int128)x - subtrahend);
    return (br_word_t)(((unsigned __int128)x < subtrahend) ? 1 : 0);
}

static inline br_word_t br_value_barrier(br_word_t a) { return a; }
static inline br_word_t br_declassify(br_word_t a) { return a; }

static inline br_word_t br_broadcast_negative(br_word_t x) {
    return (br_signed_t)x >> 63;
}

static inline br_word_t br_broadcast_nonzero(br_word_t x) {
    return br_broadcast_negative(x | (0u - x));
}

static inline br_word_t br_cmov(br_word_t c, br_word_t vnz, br_word_t vz) {
    return c ? vnz : vz;
}

static inline br_word_t _br_load(br_word_t a) {
    br_word_t r = 0;
    memcpy(&r, (const void *)a, sizeof(r));
    return r;
}

static inline void _br_store(br_word_t a, br_word_t v) {
    memcpy((void *)a, &v, sizeof(v));
}

static inline void br_memcpy(br_word_t d, br_word_t s, br_word_t n) {
    memcpy((void *)d, (const void *)s, (size_t)n);
}

static inline void br_memset(br_word_t d, br_word_t v, br_word_t n) {
    memset((void *)d, (int)v, (size_t)n);
}

static inline void br_memcxor(br_word_t d, br_word_t s, br_word_t n, br_word_t mask) {
    uint8_t *dst = (uint8_t *)d;
    const uint8_t *src = (const uint8_t *)s;
    const uint8_t m = (uint8_t)mask;
    for (size_t i = 0; i < (size_t)n; i++) dst[i] ^= src[i] & m;
}

void zig_tls_p256_coord_mul(uint64_t out[4], const uint64_t x[4], const uint64_t y[4]);
void zig_tls_p256_coord_sqr(uint64_t out[4], const uint64_t x[4]);
void zig_tls_p256_fiat_opp(uint64_t out[4], const uint64_t x[4]);
void zig_tls_p256_fiat_set_one(uint64_t out[4]);

static inline void p256_coord_mul(br_word_t p_out, br_word_t p_x, br_word_t p_y) {
    zig_tls_p256_coord_mul((uint64_t *)p_out, (const uint64_t *)p_x, (const uint64_t *)p_y);
}

static inline void p256_coord_sqr(br_word_t p_out, br_word_t p_x) {
    zig_tls_p256_coord_sqr((uint64_t *)p_out, (const uint64_t *)p_x);
}

static inline void fiat_p256_opp_conditional(br_word_t out, br_word_t in, br_word_t cond) {
    uint64_t neg[4];
    zig_tls_p256_fiat_opp(neg, (const uint64_t *)(uintptr_t)in);
    const uint64_t mask = -(uint64_t)(cond & 1);
    for (int i = 0; i < 4; i++) {
        const uint64_t v = _br_load(out + (br_word_t)i * 8);
        const uint64_t src = _br_load(in + (br_word_t)i * 8);
        _br_store(out + (br_word_t)i * 8, (neg[i] & mask) | (src & ~mask));
    }
}

#include "p256_field_64.br.c.inc"
#include "p256_point.br.c.inc"
