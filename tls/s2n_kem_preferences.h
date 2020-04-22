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

#include "tls/s2n_kem.h"
#include "tls/s2n_kex.h"

struct s2n_kem_preferences {
    uint8_t count;
    const struct s2n_kem **kems;
};

#if !defined(S2N_NO_PQ)

extern const struct s2n_kem *pq_kems_r1[2];
extern const struct s2n_kem *pq_kems_r2r1[4];
extern const struct s2n_kem *pq_kems_sike_r1[1];
extern const struct s2n_kem *pq_kems_sike_r2r1[2];

extern const struct s2n_kem_preferences kem_preferences_kms_pq_tls_1_0_2019_06;
extern const struct s2n_kem_preferences kem_preferences_kms_pq_tls_1_0_2020_02;
extern const struct s2n_kem_preferences kem_preferences_pq_sike_test_tls_1_0_2019_11;
extern const struct s2n_kem_preferences kem_preferences_pq_sike_test_tls_1_0_2020_02;

#endif

extern const struct s2n_kem_preferences kem_preferences_null;
