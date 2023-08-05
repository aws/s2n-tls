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

const struct s2n_kem *pq_kems_r3_2021_05[] = {
    /* Round 3 Algorithms */
    &s2n_kyber_512_r3,
};

const struct s2n_kem_group *pq_kem_groups_r3_2021_05[] = {
#if EVP_APIS_SUPPORTED
    &s2n_x25519_kyber_512_r3,
#endif
    &s2n_secp256r1_kyber_512_r3,
};

const struct s2n_kem_group *pq_kem_groups_r3_2023_06[] = {
#if defined(S2N_LIBCRYPTO_SUPPORTS_KYBER)
    &s2n_secp256r1_kyber_768_r3,
    #if EVP_APIS_SUPPORTED
    &s2n_x25519_kyber_768_r3,
    #endif
    &s2n_secp384r1_kyber_768_r3,
    &s2n_secp521r1_kyber_1024_r3,
#endif
    &s2n_secp256r1_kyber_512_r3,
#if EVP_APIS_SUPPORTED
    &s2n_x25519_kyber_512_r3,
#endif
};

const struct s2n_kem_preferences kem_preferences_pq_tls_1_0_2021_05 = {
    .kem_count = s2n_array_len(pq_kems_r3_2021_05),
    .kems = pq_kems_r3_2021_05,
    .tls13_kem_group_count = s2n_array_len(pq_kem_groups_r3_2021_05),
    .tls13_kem_groups = pq_kem_groups_r3_2021_05,
    .tls13_pq_hybrid_draft_revision = 0
};

const struct s2n_kem_preferences kem_preferences_pq_tls_1_0_2023_01 = {
    .kem_count = s2n_array_len(pq_kems_r3_2021_05),
    .kems = pq_kems_r3_2021_05,
    .tls13_kem_group_count = s2n_array_len(pq_kem_groups_r3_2021_05),
    .tls13_kem_groups = pq_kem_groups_r3_2021_05,
    .tls13_pq_hybrid_draft_revision = 5
};

/* TLS 1.3 specifies KEMS via SupportedGroups extension, not TLS 1.2's KEM-specific extension. */
const struct s2n_kem_preferences kem_preferences_pq_tls_1_3_2023_06 = {
    .kem_count = 0,
    .kems = NULL,
    .tls13_kem_group_count = s2n_array_len(pq_kem_groups_r3_2023_06),
    .tls13_kem_groups = pq_kem_groups_r3_2023_06,
    .tls13_pq_hybrid_draft_revision = 5
};

const struct s2n_kem_preferences kem_preferences_all = {
    .kem_count = s2n_array_len(pq_kems_r3_2021_05),
    .kems = pq_kems_r3_2021_05,
    .tls13_kem_group_count = s2n_array_len(pq_kem_groups_r3_2023_06),
    .tls13_kem_groups = pq_kem_groups_r3_2023_06,
    .tls13_pq_hybrid_draft_revision = 5
};

const struct s2n_kem_preferences kem_preferences_null = {
    .kem_count = 0,
    .kems = NULL,
    .tls13_kem_group_count = 0,
    .tls13_kem_groups = NULL,
    .tls13_pq_hybrid_draft_revision = 0
};

/* Determines if query_iana_id corresponds to a tls13_kem_group for these KEM preferences. */
bool s2n_kem_preferences_includes_tls13_kem_group(const struct s2n_kem_preferences *kem_preferences,
        uint16_t query_iana_id)
{
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

/* Whether the client must include the length prefix in the PQ TLS 1.3 KEM KeyShares that it sends. Draft 0 of
 * the PQ TLS 1.3 standard required length prefixing, and drafts 1-5 removed this length prefix. To not break
 * backwards compatibility, we check what revision of the draft standard is configured to determine whether to send it. */
bool s2n_tls13_client_must_use_hybrid_kem_length_prefix(const struct s2n_kem_preferences *kem_pref)
{
    return kem_pref && (kem_pref->tls13_pq_hybrid_draft_revision == 0);
}
