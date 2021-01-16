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

#include "tls/s2n_kem_preferences.h"

/* Extension list for round 1 PQ KEMs, in order of preference */
const struct s2n_kem *pq_kems_r1[2] = {
    &s2n_bike1_l1_r1,
    &s2n_sike_p503_r1,
};

/* Extension list for round 2 and round 1 PQ KEMs, in order of preference */
const struct s2n_kem *pq_kems_r2r1[4] = {
    &s2n_bike1_l1_r2,
    &s2n_sike_p434_r2,
    &s2n_bike1_l1_r1,
    &s2n_sike_p503_r1,
};

const struct s2n_kem *pq_kems_r2r1_2020_07[5] = {
    &s2n_kyber_512_r2,
    &s2n_bike1_l1_r2,
    &s2n_sike_p434_r2,
    &s2n_bike1_l1_r1,
    &s2n_sike_p503_r1,
};

/* Extension list for SIKE P503 Round 1 only (for testing) */
const struct s2n_kem *pq_kems_sike_r1[1] = {
    &s2n_sike_p503_r1,
};

/* Extension list for SIKE P434 Round 2 and SIKE P503 Round 1 only (for testing),
 * in order of preference */
const struct s2n_kem *pq_kems_sike_r2r1[2] = {
    &s2n_sike_p434_r2,
    &s2n_sike_p503_r1,
};

const struct s2n_kem_group *pq_kem_groups_r2[] = {
#if EVP_APIS_SUPPORTED
        &s2n_x25519_kyber_512_r2,
        &s2n_secp256r1_kyber_512_r2,
        &s2n_x25519_bike1_l1_r2,
        &s2n_secp256r1_bike1_l1_r2,
        &s2n_x25519_sike_p434_r2,
        &s2n_secp256r1_sike_p434_r2,
#else
        &s2n_secp256r1_kyber_512_r2,
        &s2n_secp256r1_bike1_l1_r2,
        &s2n_secp256r1_sike_p434_r2,
#endif
};

/* Includes only round 1 PQ KEM params */
const struct s2n_kem_preferences kem_preferences_kms_pq_tls_1_0_2019_06 = {
    .kem_count = s2n_array_len(pq_kems_r1),
    .kems = pq_kems_r1,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
};

/* Includes round 1 and round 2 PQ KEM params. */
const struct s2n_kem_preferences kem_preferences_kms_pq_tls_1_0_2020_02 = {
    .kem_count = s2n_array_len(pq_kems_r2r1),
    .kems = pq_kems_r2r1,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
};

const struct s2n_kem_preferences kem_preferences_kms_pq_tls_1_0_2020_07 = {
    .kem_count = s2n_array_len(pq_kems_r2r1_2020_07),
    .kems = pq_kems_r2r1_2020_07,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
};

/* Includes only SIKE round 1 (for integration tests) */
const struct s2n_kem_preferences kem_preferences_pq_sike_test_tls_1_0_2019_11 = {
    .kem_count = s2n_array_len(pq_kems_sike_r1),
    .kems = pq_kems_sike_r1,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
};

/* Includes only SIKE round 1 and round 2 (for integration tests). */
const struct s2n_kem_preferences kem_preferences_pq_sike_test_tls_1_0_2020_02 = {
    .kem_count = s2n_array_len(pq_kems_sike_r2r1),
    .kems = pq_kems_sike_r2r1,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
};

const struct s2n_kem_preferences kem_preferences_pq_tls_1_0_2020_12 = {
    .kem_count = s2n_array_len(pq_kems_r2r1_2020_07),
    .kems = pq_kems_r2r1_2020_07,
    .tls13_kem_group_count = s2n_array_len(pq_kem_groups_r2),
    .tls13_kem_groups = pq_kem_groups_r2,
};

const struct s2n_kem_preferences kem_preferences_null = {
    .kem_count = 0,
    .kems = NULL,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
};

/* Determines if query_iana_id corresponds to a tls13_kem_group for these KEM preferences. */
bool s2n_kem_preferences_includes_tls13_kem_group(const struct s2n_kem_preferences *kem_preferences,
        uint16_t query_iana_id) {
    if (kem_preferences == NULL) {
        return false;
    }

    for (size_t i = 0; i < kem_preferences->tls13_kem_group_count; i++) {
        if (query_iana_id == kem_preferences->tls13_kem_groups[i]->iana_id) {
            return true;
        }
    }

    return false;
}
