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

#include "crypto/s2n_fips.h"
#include "pq-crypto/s2n_pq_asm.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

bool s2n_kyber512r3_is_avx2_bmi2_enabled(void);
S2N_RESULT s2n_try_enable_kyber512r3_opt_avx2_bmi2(void);
S2N_RESULT s2n_disable_kyber512r3_opt_avx2_bmi2(void);

bool s2n_pq_is_enabled(void);
bool s2n_libcrypto_supports_kyber(void);
S2N_RESULT s2n_pq_init(void);
