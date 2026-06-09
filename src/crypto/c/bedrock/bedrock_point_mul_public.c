#include "openssl_shim.h"
#include "bedrock_platform.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t fiat_p256_felem[4];

#define OPENSSL_64_BIT 1
#include "p256_table.h"

static uint64_t scalar_bit(const uint8_t in[32], int i) {
    if (i < 0 || i >= 256) {
        return 0;
    }
    return (in[i >> 3] >> (i & 7)) & 1;
}

static void ec_compute_wNAF(int8_t *out, const uint8_t scalar[32], size_t bits, int w) {
    assert(0 < w && w <= 7);
    assert(bits != 0);
    int bitw = 1 << w;
    int next_bit = bitw << 1;
    int mask = next_bit - 1;

    uint64_t word0;
    memcpy(&word0, scalar, sizeof(word0));
    int window_val = (int)(word0 & (uint64_t)mask);
    for (size_t j = 0; j < bits + 1; j++) {
        int digit = 0;
        if (window_val & 1) {
            if (window_val & bitw) {
                digit = window_val - next_bit;
                if (j + (size_t)w + 1 >= bits) {
                    digit = window_val & (mask >> 1);
                }
            } else {
                digit = window_val;
            }
            window_val -= digit;
        }
        out[j] = (int8_t)digit;
        window_val >>= 1;
        if (scalar_bit(scalar, (int)(j + (size_t)w + 1))) {
            window_val += bitw;
        }
    }
}

static bool p256_point_iszero_limbs(const fiat_p256_felem p[3]) {
    uint64_t acc = 0;
    for (int c = 0; c < 3; c++) {
        for (int i = 0; i < 4; i++) {
            acc |= p[c][i];
        }
    }
    return acc == 0;
}

void p256_bedrock_point_mul_public(uint64_t out[3][4], const uint8_t g_scalar[32],
                                   const uint64_t p_in[3][4], const uint8_t p_scalar[32]) {
    int8_t p_wNAF[257] = {0};
    alignas(32) fiat_p256_felem p_pre_comp[8][3];

    memcpy(p_pre_comp[0][2], p_in[2], 32);
    if (!p256_point_iszero_limbs(p_pre_comp[0])) {
        ec_compute_wNAF(p_wNAF, p_scalar, 256, 4);
        memcpy(p_pre_comp[0][0], p_in[0], 32);
        memcpy(p_pre_comp[0][1], p_in[1], 32);
        alignas(32) fiat_p256_felem p2[3];
        p256_point_double((br_word_t)p2, (br_word_t)p_pre_comp[0]);
        for (size_t i = 1; i < 8; i++) {
            p256_point_add_nz_nz_neq((br_word_t)p_pre_comp[i], (br_word_t)p_pre_comp[i - 1],
                                     (br_word_t)p2);
        }
    }

    alignas(32) fiat_p256_felem ret[3] = {};
    bool ret_is_zero = true;
    for (int i = 256; i >= 0; i--) {
        if (!ret_is_zero) {
            p256_point_double((br_word_t)ret, (br_word_t)ret);
        }

        if (i <= 31) {
            for (size_t j = 1; j < 2; j--) {
                uint64_t bits = 0;
                for (size_t k = 3; k < 4; k--) {
                    bits |= scalar_bit(g_scalar, i + (int)(j * 32 + k * 64)) << k;
                }
                if (bits != 0) {
                    if (!ret_is_zero) {
                        alignas(32) fiat_p256_felem t[3];
                        zig_tls_p256_fiat_set_one(t[2]);
                        memcpy(t, fiat_p256_g_pre_comp[j][bits - 1], 64);
                        p256_point_add_affinenz_conditional_vartime_if_doubling(
                            (br_word_t)ret, (br_word_t)ret, (br_word_t)t, 1);
                        ret_is_zero = p256_point_iszero((br_word_t)ret);
                    } else {
                        memcpy(ret, fiat_p256_g_pre_comp[j][bits - 1], 64);
                        zig_tls_p256_fiat_set_one(ret[2]);
                        ret_is_zero = false;
                    }
                }
            }
        }

        int digit = p_wNAF[i];
        if (digit != 0) {
            size_t idx = (size_t)(digit < 0 ? (-digit) >> 1 : digit >> 1);
            fiat_p256_felem t[3];
            memcpy(t, p_pre_comp[idx], sizeof(t));
            if (digit < 0) {
                zig_tls_p256_fiat_opp(t[1], t[1]);
            }
            if (!ret_is_zero) {
                p256_point_add_vartime_if_doubling((br_word_t)ret, (br_word_t)ret, (br_word_t)t);
                ret_is_zero = p256_point_iszero((br_word_t)ret);
            } else {
                memcpy(ret, t, sizeof(ret));
                ret_is_zero = false;
            }
        }
    }

    memcpy(out, ret, sizeof(ret));
}
