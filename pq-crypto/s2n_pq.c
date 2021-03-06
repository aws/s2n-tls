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

static bool sikep434r2_asm_enabled = false;

#if defined(S2N_CPUID_AVAILABLE)
/* https://en.wikipedia.org/wiki/CPUID */
#include <cpuid.h>

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

bool s2n_cpu_supports_sikep434r2_asm() {
#if defined(S2N_SIKEP434R2_ASM)
    /* The sikep434r2 assembly code always requires BMI2. If the assembly
     * was compiled with support for ADX, we also require ADX at runtime. */
    #if defined(S2N_ADX)
        return s2n_cpu_supports_bmi2() && s2n_cpu_supports_adx();
    #else
        return s2n_cpu_supports_bmi2();
    #endif
#else
    /* sikep434r2 assembly was not supported at compile time */
    return false;
#endif /* defined(S2N_SIKEP434R2_ASM) */
}

#else /* defined(S2N_CPUID_AVAILABLE) */

/* If CPUID is not available, we cannot perform necessary run-time checks. */
bool s2n_cpu_supports_sikep434r2_asm() {
    return false;
}

#endif /* defined(S2N_CPUID_AVAILABLE) */

bool s2n_sikep434r2_asm_is_enabled() {
    return sikep434r2_asm_enabled;
}

bool s2n_pq_is_enabled() {
#if defined(S2N_NO_PQ)
    return false;
#else
    return !s2n_is_in_fips_mode();
#endif
}

S2N_RESULT s2n_disable_sikep434r2_asm() {
    sikep434r2_asm_enabled = false;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_sikep434r2_asm() {
    if (s2n_pq_is_enabled() && s2n_cpu_supports_sikep434r2_asm()) {
        sikep434r2_asm_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_pq_init() {
    RESULT_ENSURE_OK(s2n_try_enable_sikep434r2_asm(), S2N_ERR_SAFETY);

    return S2N_RESULT_OK;
}
