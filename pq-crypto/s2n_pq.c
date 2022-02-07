/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_pq.h"
#include "crypto/s2n_openssl.h"

static bool sikep434r3_asm_enabled = false;

/* BIKE Round-3 code supports several levels of optimization */
static bool bike_r3_avx2_enabled    = false;
static bool bike_r3_avx512_enabled  = false;
static bool bike_r3_pclmul_enabled  = false;
static bool bike_r3_vpclmul_enabled = false;

static bool kyber512r3_avx2_bmi2_enabled = false;

#if defined(S2N_CPUID_AVAILABLE)
/* https://en.wikipedia.org/wiki/CPUID */
#include <cpuid.h>

#define PROCESSOR_INFO_AND_FEATURES    1
#define EXTENDED_FEATURES_LEAF         7
#define EXTENDED_FEATURES_SUBLEAF_ZERO 0

/* The cpuid.h header included with older versions of gcc and
 * clang doesn't include definitions for bit_ADX, bit_BMI2, or
 * __get_cpuid_count(). */
#if !defined(bit_ADX)
    #define bit_ADX (1 << 19)
#endif

#if !defined(bit_BMI2)
    #define bit_BMI2 (1 << 8)
#endif

/* BIKE related CPU features */
#define EBX_BIT_AVX2    (1 << 5)
#define EBX_BIT_AVX512  (1 << 16)
#define ECX_BIT_VPCLMUL (1 << 10)
#define ECX_BIT_PCLMUL  (1 << 1)

bool s2n_get_cpuid_count(uint32_t leaf, uint32_t sub_leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    /* 0x80000000 probes for extended cpuid info */
    uint32_t max_level = __get_cpuid_max(leaf & 0x80000000, 0);

    if (max_level == 0 || max_level < leaf) {
        return false;
    }

    __cpuid_count(leaf, sub_leaf, *eax, *ebx, *ecx, *edx);
    return true;
}

/* https://en.wikipedia.org/wiki/Bit_manipulation_instruction_set#BMI2_(Bit_Manipulation_Instruction_Set_2) */
bool s2n_cpu_supports_bmi2() {
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(EXTENDED_FEATURES_LEAF, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    return (ebx & bit_BMI2);
}

/* https://en.wikipedia.org/wiki/Intel_ADX */
bool s2n_cpu_supports_adx() {
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(EXTENDED_FEATURES_LEAF, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    return (ebx & bit_ADX);
}

bool s2n_cpu_supports_avx2() {
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(EXTENDED_FEATURES_LEAF, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    return (ebx & EBX_BIT_AVX2);
}

bool s2n_cpu_supports_sikep434r3_asm() {
#if defined(S2N_SIKE_P434_R3_ASM)
    /* The sikep434r3 assembly code always requires BMI2. If the assembly
     * was compiled with support for ADX, we also require ADX at runtime. */
#if defined(S2N_ADX)
    return s2n_cpu_supports_bmi2() && s2n_cpu_supports_adx();
#else
    return s2n_cpu_supports_bmi2();
#endif
#else
    /* sikep434r3 assembly was not supported at compile time */
    return false;
#endif /* defined(S2N_SIKE_P434_R3_ASM) */
}

bool s2n_cpu_supports_bike_r3_avx2() {
#if defined(S2N_BIKE_R3_AVX2)
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(EXTENDED_FEATURES_LEAF, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    return ((ebx & EBX_BIT_AVX2) != 0);
#else
    return false;
#endif
}

bool s2n_cpu_supports_bike_r3_avx512() {
#if defined(S2N_BIKE_R3_AVX512)
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(EXTENDED_FEATURES_LEAF, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    return ((ebx & EBX_BIT_AVX512) != 0);
#else
    return false;
#endif
}

bool s2n_cpu_supports_bike_r3_pclmul() {
#if defined(S2N_BIKE_R3_PCLMUL)
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(PROCESSOR_INFO_AND_FEATURES, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    return ((ecx & ECX_BIT_PCLMUL) != 0);
#else
    return false;
#endif
}

bool s2n_cpu_supports_bike_r3_vpclmul() {
#if defined(S2N_BIKE_R3_AVX512)
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(EXTENDED_FEATURES_LEAF, EXTENDED_FEATURES_SUBLEAF_ZERO, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    return ((ecx & ECX_BIT_VPCLMUL) != 0);
#else
    return false;
#endif
}

bool s2n_cpu_supports_kyber512r3_avx2_bmi2() {
#if defined(S2N_KYBER512R3_AVX2_BMI2)
    return s2n_cpu_supports_bmi2() && s2n_cpu_supports_avx2();
#else
    return false;
#endif
}

#else /* defined(S2N_CPUID_AVAILABLE) */

/* If CPUID is not available, we cannot perform necessary run-time checks. */
bool s2n_cpu_supports_sikep434r3_asm() {
    return false;
}

bool s2n_cpu_supports_bike_r3_avx2() {
    return false;
}

bool s2n_cpu_supports_bike_r3_avx512() {
    return false;
}

bool s2n_cpu_supports_bike_r3_pclmul() {
    return false;
}

bool s2n_cpu_supports_bike_r3_vpclmul() {
    return false;
}

bool s2n_cpu_supports_kyber512r3_avx2_bmi2() {
    return false;
}

#endif /* defined(S2N_CPUID_AVAILABLE) */

bool s2n_sikep434r3_asm_is_enabled() {
    return sikep434r3_asm_enabled;
}

bool s2n_bike_r3_is_avx2_enabled() {
    return bike_r3_avx2_enabled;
}

bool s2n_bike_r3_is_avx512_enabled() {
    return bike_r3_avx512_enabled;
}

bool s2n_bike_r3_is_pclmul_enabled() {
    return bike_r3_pclmul_enabled;
}

bool s2n_bike_r3_is_vpclmul_enabled() {
    return bike_r3_vpclmul_enabled;
}

bool s2n_kyber512r3_is_avx2_bmi2_enabled() {
    return kyber512r3_avx2_bmi2_enabled;
}

bool s2n_pq_is_enabled() {
#if defined(S2N_NO_PQ)
    return false;
#else
    /* aws-lc is currently the only supported FIPS library known to support PQ. */
    return s2n_libcrypto_is_awslc() || (!s2n_is_in_fips_mode());
#endif
}

S2N_RESULT s2n_disable_sikep434r3_asm() {
    sikep434r3_asm_enabled = false;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_disable_bike_r3_opt_all() {
    bike_r3_avx2_enabled    = false;
    bike_r3_avx512_enabled  = false;
    bike_r3_pclmul_enabled  = false;
    bike_r3_vpclmul_enabled = false;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_disable_kyber512r3_opt_avx2_bmi2() {
    kyber512r3_avx2_bmi2_enabled = false;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_bike_r3_opt_pclmul() {
    if (s2n_pq_is_enabled() && s2n_cpu_supports_bike_r3_pclmul()) {
        bike_r3_pclmul_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_bike_r3_opt_avx2() {
    /* When AVX2 is available, PCLMUL is too by default. */
    RESULT_ENSURE_OK(s2n_try_enable_bike_r3_opt_pclmul(), S2N_ERR_SAFETY);
    if (s2n_pq_is_enabled() && s2n_cpu_supports_bike_r3_avx2()) {
        bike_r3_avx2_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_bike_r3_opt_avx512() {
    /* When AVX512 is available, AVX2 is too by default. */
    RESULT_ENSURE_OK(s2n_try_enable_bike_r3_opt_avx2(), S2N_ERR_SAFETY);
    if (s2n_pq_is_enabled() && s2n_cpu_supports_bike_r3_avx512()) {
        bike_r3_avx512_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_bike_r3_opt_vpclmul() {
    RESULT_ENSURE_OK(s2n_try_enable_bike_r3_opt_avx512(), S2N_ERR_SAFETY);
    /* Only Enable VPCLMUL if AVX512 is also supported. This is to because the BIKE R3 VPCLMUL requires 512-bit version
     * of VPCLMUL, and not the 256-bit version that is available on AMD Zen 3 processors. */
    if (s2n_pq_is_enabled() && s2n_cpu_supports_bike_r3_vpclmul() && s2n_bike_r3_is_avx512_enabled()) {
        bike_r3_vpclmul_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_sikep434r3_asm() {
    if (s2n_pq_is_enabled() && s2n_cpu_supports_sikep434r3_asm()) {
        sikep434r3_asm_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_kyber512r3_opt_avx2_bmi2() {
    if (s2n_pq_is_enabled() && s2n_cpu_supports_kyber512r3_avx2_bmi2()) {
        kyber512r3_avx2_bmi2_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_bike_r3_x86_64_opt_init()
{
    /* try_enable_vpclmul function recursively tries to enable
     * all the optimizations (avx2, avx512, pclmul, vpclmul),
     * so it's sufficient to call only this function. */
    RESULT_ENSURE_OK(s2n_try_enable_bike_r3_opt_vpclmul(), S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_pq_init() {
    RESULT_ENSURE_OK(s2n_try_enable_sikep434r3_asm(), S2N_ERR_SAFETY);
    RESULT_ENSURE_OK(s2n_bike_r3_x86_64_opt_init(), S2N_ERR_SAFETY);
    RESULT_ENSURE_OK(s2n_try_enable_kyber512r3_opt_avx2_bmi2(), S2N_ERR_SAFETY);
    
    return S2N_RESULT_OK;
}
