#include "openssl_shim.h"
#include "bedrock_platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t fiat_p256_felem[4];
typedef fiat_p256_felem PRECOMP256_ROW[64][2];
#include "p256-nistz-table.h"

static uint64_t booth_recode_w7(uint64_t in) {
    uint64_t s = ~((in >> 7) - 1);
    uint64_t d = ((uint64_t)1 << 8) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);
    return (d << 1) + (s & 1);
}

static void select_affine_16(fiat_p256_felem dst[2], const fiat_p256_felem src[16][2], size_t i) {
    memset(dst, 0, 2 * sizeof(fiat_p256_felem));
    if (i < 16) {
        memcpy(dst, src[i], 2 * sizeof(fiat_p256_felem));
    }
}

static void select_affine_64(fiat_p256_felem dst[2], const fiat_p256_felem src[64][2], size_t i) {
    memset(dst, 0, 2 * sizeof(fiat_p256_felem));
    if (i < 64) {
        memcpy(dst, src[i], 2 * sizeof(fiat_p256_felem));
    }
}

void p256_bedrock_mul_base(uint64_t out[3][4], const uint8_t s[32]) {
    bool ret_is_zero = true;
    fiat_p256_felem t[3];
    zig_tls_p256_fiat_set_one(t[2]);

    for (size_t i = 36; i < 37; i--) {
        const uint64_t k_mask = ((uint64_t)1 << 8) - 1;
        uint64_t wvalue;
        if (i == 0) {
            wvalue = ((uint64_t)s[0] << 1) & k_mask;
        } else {
            const size_t first_bit = 7 * i - 1;
            const size_t idx = first_bit / 8;
            wvalue = s[idx] | ((uint64_t)(idx < 31 ? s[idx + 1] : 0) << 8);
            wvalue = (wvalue >> (first_bit % 8)) & k_mask;
        }
        wvalue = booth_recode_w7(wvalue);
        if (i == 36) {
            select_affine_16(t, ecp_nistz256_precomputed[i], (wvalue >> 1) - 1);
        } else {
            select_affine_64(t, ecp_nistz256_precomputed[i], (wvalue >> 1) - 1);
        }
        fiat_p256_opp_conditional((br_word_t)(uintptr_t)t[1], (br_word_t)(uintptr_t)t[1], wvalue & 1);

        if (!ret_is_zero) {
            p256_point_add_affinenz_conditional_vartime_if_doubling(
                (br_word_t)out, (br_word_t)out, (br_word_t)t, (br_word_t)(wvalue >> 1));
        } else {
            memcpy(out, t, sizeof(t));
            if ((wvalue >> 1) == 0) {
                memset(out[2], 0, sizeof(out[2]));
            } else {
                zig_tls_p256_fiat_set_one(out[2]);
            }
            ret_is_zero = false;
        }
    }
}
