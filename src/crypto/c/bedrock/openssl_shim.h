#pragma once

#include <stdint.h>

#define TOBN(a, b) ((((uint64_t)(uint32_t)(a)) << 32) | ((uint64_t)(uint32_t)(b)))

#if defined(__GNUC__) || defined(__clang__)
#define alignas(x) __attribute__((aligned(x)))
#else
#define alignas(x)
#endif
