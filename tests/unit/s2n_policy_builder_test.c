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

#include "tls/policy/s2n_policy_builder.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_test_strict_compatibility(uint64_t start, uint64_t end,
        struct s2n_test_cert_chain_list *cert_chains)
{
    for (size_t client_i = start; client_i <= end; client_i++) {
        for (size_t server_i = start; server_i <= end; server_i++) {
            for (size_t cert_i = 0; cert_i < cert_chains->count; cert_i++) {
                DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(config);
                EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config,
                        cert_chains->chains[cert_i].chain));
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(client, config));
                EXPECT_SUCCESS(s2n_connection_set_security_policy(client,
                        s2n_security_policy_get(S2N_POLICY_STRICT, client_i)));

                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));
                EXPECT_SUCCESS(s2n_connection_set_security_policy(server,
                        s2n_security_policy_get(S2N_POLICY_STRICT, server_i)));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

                /* For now, consider a HRR a potential breaking change.
                 * We can revisit later if necessary.
                 */
                EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server));
            }
        }
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_security_policy_get */
    {
        /* Policies exist only for expected policy + version combinations */
        for (size_t policy_i = 0; policy_i < UINT8_MAX; policy_i++) {
            bool first_null_found = false;
            uint64_t versions_found = 0;

            for (size_t version_i = 0; version_i < UINT8_MAX; version_i++) {
                const struct s2n_security_policy *policy = s2n_security_policy_get(policy_i, version_i);

                /* Invalid policy or version values should be NULL */
                if (version_i == 0 || policy_i == 0) {
                    /* Versioning starts at 1 instead of 0.
                     * We may want to later assign 0 a special meaning, like "none".
                     */
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                    continue;
                } else if (policy_i >= S2N_MAX_DEFAULT_POLICIES) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                    continue;
                } else if (version_i >= S2N_MAX_POLICY_VERSIONS) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                    continue;
                }

                if (policy) {
                    /* The policy exists because the version is valid.
                     * Versions should be contiguous. No previous gaps.
                     */
                    EXPECT_FALSE(first_null_found);
                    versions_found++;
                } else if (first_null_found) {
                    /* If we've already found the first invalid version, all later
                     * versions should be invalid too.
                     */
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                } else {
                    /* We have found the first invalid version */
                    first_null_found = true;
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                }
            }

            if (policy_i > 0 && policy_i < S2N_MAX_DEFAULT_POLICIES) {
                /* Each valid policy should have at least one valid version */
                EXPECT_TRUE(versions_found > 0);
                /* If we did't find the last valid version, we're not testing enough */
                EXPECT_TRUE(first_null_found);
            }
        };

        /* Check known good values.
         * Note: don't add EVERY new version to this test. We should only test
         * an interesting selection of inputs.
         */
        {
            EXPECT_NOT_NULL(s2n_security_policy_get(S2N_POLICY_STRICT, S2N_STRICT_2025_08_20));
            EXPECT_NOT_NULL(s2n_security_policy_get(S2N_POLICY_COMPATIBLE, S2N_COMPAT_2025_08_20));
        }
    };

    /* Test: S2N_POLICY_STRICT backwards compatibility promises enforced */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_test_cert_chain_list cert_chains = { 0 }, s2n_test_cert_chains_free);
        EXPECT_OK(s2n_test_cert_chains_init(&cert_chains));

        EXPECT_OK(s2n_test_strict_compatibility(1, S2N_STRICT_LATEST_1, &cert_chains));
    };

    END_TEST();
}
