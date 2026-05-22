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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Self-talk test */
    {
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        /* Test both composite and non-composite CBC ciphers for all CBC cipher suites. */
        size_t record_algs_tested = 0;
        for (size_t cipher_suite_idx = 0; cipher_suite_idx < cipher_preferences_test_all.count; cipher_suite_idx++) {
            uint8_t record_algs = cipher_preferences_test_all.suites[cipher_suite_idx]->num_record_algs;
            for (size_t record_alg_idx = 0; record_alg_idx < record_algs; record_alg_idx++) {
                struct s2n_cipher_suite test_cipher_suite = *cipher_preferences_test_all.suites[cipher_suite_idx];
                test_cipher_suite.record_alg = test_cipher_suite.all_record_algs[record_alg_idx];

                /* Skip non-CBC ciphers. */
                uint8_t cipher = test_cipher_suite.record_alg->cipher->type;
                if (cipher != S2N_CBC && cipher != S2N_COMPOSITE) {
                    continue;
                }

                /* Skip unsupported ciphers. */
                if (!test_cipher_suite.record_alg->cipher->is_available()) {
                    continue;
                }

                struct s2n_cipher_suite *test_cipher_suite_ptr = &test_cipher_suite;
                struct s2n_cipher_preferences test_cipher_preferences = {
                    .count = 1,
                    .suites = &test_cipher_suite_ptr,
                };

                struct s2n_security_policy test_security_policy = security_policy_test_all;
                test_security_policy.cipher_preferences = &test_cipher_preferences;

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client);
                EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
                client->security_policy_override = &test_security_policy;

                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server);
                EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
                server->security_policy_override = &test_security_policy;

                DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connection_set_io_pair(client, &io_pair));
                EXPECT_SUCCESS(s2n_connection_set_io_pair(server, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

                uint8_t negotiated_cipher_suite[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
                EXPECT_SUCCESS(s2n_connection_get_cipher_iana_value(server, negotiated_cipher_suite,
                        negotiated_cipher_suite + 1));
                EXPECT_BYTEARRAY_EQUAL(negotiated_cipher_suite, test_cipher_suite.iana_value,
                        S2N_TLS_CIPHER_SUITE_LEN);

                EXPECT_OK(s2n_send_and_recv_test(client, server));
                EXPECT_OK(s2n_send_and_recv_test(server, client));

                record_algs_tested += 1;
            }
        }

        EXPECT_TRUE(record_algs_tested > 0);
    }

    END_TEST();
}
