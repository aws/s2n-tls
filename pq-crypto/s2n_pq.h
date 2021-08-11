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

#pragma once

#include <stdbool.h>
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_fips.h"

bool s2n_sikep434r3_asm_is_enabled(void);
S2N_RESULT s2n_disable_sikep434r3_asm(void);
S2N_RESULT s2n_try_enable_sikep434r3_asm(void);

bool s2n_bike_r3_is_avx2_enabled(void);
bool s2n_bike_r3_is_avx512_enabled(void);
bool s2n_bike_r3_is_pclmul_enabled(void);
bool s2n_bike_r3_is_vpclmul_enabled(void);
S2N_RESULT s2n_disable_bike_r3_opt_all(void);
S2N_RESULT s2n_try_enable_bike_r3_opt_pclmul(void);
S2N_RESULT s2n_try_enable_bike_r3_opt_avx2(void);
S2N_RESULT s2n_try_enable_bike_r3_opt_avx512(void);
S2N_RESULT s2n_try_enable_bike_r3_opt_vpclmul(void);

bool s2n_kyber512r3_is_avx2_bmi2_enabled(void);
S2N_RESULT s2n_try_enable_kyber512r3_opt_avx2_bmi2(void);
S2N_RESULT s2n_disable_kyber512r3_opt_avx2_bmi2(void);
 
bool s2n_pq_is_enabled(void);
S2N_RESULT s2n_pq_init(void);
