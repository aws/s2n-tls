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

#include "crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

bool s2n_test_pq_kem_is_negotiated(struct s2n_connection *conn, const struct s2n_kem_preferences *expect_kem_groups)
{
    EXPECT_NOT_NULL(conn);
    /* Classical ECC is not negotiated. */
    EXPECT_EQUAL(conn->kex_params.server_ecc_evp_params.negotiated_curve, NULL);
    const struct s2n_kem_group *server_kem_group = conn->kex_params.server_kem_group_params.kem_group;

    for (size_t i = 0; i < expect_kem_groups->tls13_kem_group_count; i++) {
        if (expect_kem_groups->tls13_kem_groups[i] == server_kem_group) {
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    const char *policies[] = {
        "ELBSecurityPolicy-TLS13-1-3-PQ-ONLY-2025-09",
        "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-ONLY-2025-09",
    };

    for (int version_index = 0; version_index < s2n_array_len(policies); version_index++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, policies[version_index]));
        } else {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, policies[version_index]),
                    S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
            continue;
        }

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        const struct s2n_kem_preferences *expect_kem_groups = &kem_preferences_pq_tls_1_3_ietf_2025_07;
        uint32_t groups_available = 0;
        EXPECT_OK(s2n_kem_preferences_groups_available(expect_kem_groups, &groups_available));

        if (!s2n_pq_is_enabled()) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_API_UNSUPPORTED_BY_LIBCRYPTO);
        } else if (groups_available == 0) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
        } else {
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_TRUE(s2n_test_pq_kem_is_negotiated(server_conn, expect_kem_groups));
        }
    }

    END_TEST();
}
