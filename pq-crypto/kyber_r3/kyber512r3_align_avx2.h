#pragma once

#include <stdint.h>

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#include <immintrin.h>

#define ALIGNED_UINT8(N)        \
    union {                     \
        uint8_t coeffs[N];      \
        __m256i vec[(N+31)/32]; \
    }

#define ALIGNED_INT16(N)        \
    union {                     \
        int16_t coeffs[N];      \
        __m256i vec[(N+15)/16]; \
    }
#endif
