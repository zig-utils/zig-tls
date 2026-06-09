#include "openssl_shim.h"
#include "bedrock_platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

static uint64_t load_window(const uint8_t s[32], size_t i) {
    const uint64_t k_mask = ((uint64_t)1 << 8) - 1;
    if (i == 0) {
        return ((uint64_t)s[0] << 1) & k_mask;
    }
    const size_t first_bit = 7 * i - 1;
    const size_t idx = first_bit / 8;
    uint64_t wvalue = s[idx] | ((uint64_t)(idx < 31 ? s[idx + 1] : 0) << 8);
    return (wvalue >> (first_bit % 8)) & k_mask;
}

static void select_affine(fiat_p256_felem dst[2], const fiat_p256_felem src[64][2],
                          size_t mag, size_t row_i) {
    const size_t limit = (row_i == 36) ? 16 : 64;
    memset(dst, 0, 2 * sizeof(fiat_p256_felem));
    if (mag > 0 && mag <= limit) {
        memcpy(dst, src[mag - 1], 2 * sizeof(fiat_p256_felem));
    }
}

static void accumulate_w7_window(bool *ret_is_zero, fiat_p256_felem acc[3],
                                 const PRECOMP256_ROW row, size_t row_i,
                                 const uint8_t scalar[32]) {
    const uint64_t wvalue = booth_recode_w7(load_window(scalar, row_i));
    if ((wvalue >> 1) == 0) {
        return;
    }

    fiat_p256_felem t[3];
    select_affine(t, row, (size_t)(wvalue >> 1), row_i);
    fiat_p256_opp_conditional((br_word_t)(uintptr_t)t[1], (br_word_t)(uintptr_t)t[1],
                              wvalue & 1);

    if (!*ret_is_zero) {
        p256_point_add_affinenz_conditional_vartime_if_doubling(
            (br_word_t)acc, (br_word_t)acc, (br_word_t)t, (br_word_t)(wvalue >> 1));
    } else {
        memcpy(acc, t, sizeof(t));
        zig_tls_p256_fiat_set_one(acc[2]);
        *ret_is_zero = false;
    }
}

void p256_bedrock_mul_double_base_jacobian(uint64_t out[3][4], const uint8_t s1[32],
                                           const uint8_t s2[32],
                                           const PRECOMP256_ROW q_table[37]) {
    bool ret_is_zero = true;
    fiat_p256_felem acc[3] = {};

    for (size_t i = 36; i < 37; i--) {
        accumulate_w7_window(&ret_is_zero, acc, ecp_nistz256_precomputed[i], i, s1);
        accumulate_w7_window(&ret_is_zero, acc, q_table[i], i, s2);
    }

    memcpy(out, acc, sizeof(acc));
}
