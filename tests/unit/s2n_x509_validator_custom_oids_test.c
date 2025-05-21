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

#include "crypto/s2n_libcrypto.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_SINGLE_OID_CERT_CHAIN "../pems/custom_oids/single_oid_cert_chain.pem"
#define S2N_SINGLE_OID_KEY        "../pems/custom_oids/single_oid_key.pem"

#define S2N_MULTIPLE_OIDS_CERT_CHAIN "../pems/custom_oids/multiple_oids_cert_chain.pem"
#define S2N_MULTIPLE_OID_KEY         "../pems/custom_oids/multiple_oids_key.pem"

const char *single_oid[] = { "1.3.178.25240.2" };
const char *multiple_oids[] = { "1.3.178.25240.2", "1.3.178.25240.3" };
const int multiple_oid_count = s2n_array_len(multiple_oids);

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    {
        /* Safety Check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_custom_critical_oids(NULL, single_oid, 1), S2N_ERR_NULL);

        struct s2n_config *test_config = s2n_config_new_minimal();
        EXPECT_NOT_NULL(test_config);

#ifndef S2N_LIBCRYPTO_SUPPORTS_CUSTOM_OID
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_custom_critical_oids(test_config, single_oid, 1),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
        EXPECT_SUCCESS(s2n_config_free(test_config));

        END_TEST();
#endif

        EXPECT_SUCCESS(s2n_config_set_custom_critical_oids(test_config, single_oid, 1));
        /* invoke again to reset custom oids */
        EXPECT_SUCCESS(s2n_config_set_custom_critical_oids(test_config, multiple_oids, multiple_oid_count));
        EXPECT_EQUAL(sk_ASN1_OBJECT_num(test_config->custom_crit_oids), multiple_oid_count);
        EXPECT_SUCCESS(s2n_config_free(test_config));

        /* clang-format off */
        struct {
            const char *cert_pem_path;
            const char *key_pem_path;
            const char **custom_critical_oids;
            uint32_t custom_oid_count;
            unsigned set_oids : 1;
            s2n_error expected_error;
        } test_cases[] = {
            {
                .cert_pem_path = S2N_SINGLE_OID_CERT_CHAIN,
                .key_pem_path = S2N_SINGLE_OID_KEY,
                .custom_critical_oids = single_oid,
                .custom_oid_count = 1,
                .set_oids = true,
                .expected_error = S2N_ERR_OK,
            },

            {
                .cert_pem_path = S2N_MULTIPLE_OIDS_CERT_CHAIN,
                .key_pem_path = S2N_MULTIPLE_OID_KEY,
                .custom_critical_oids = multiple_oids,
                .custom_oid_count = multiple_oid_count,
                .set_oids = true,
                .expected_error = S2N_ERR_OK,
            },

            /* Validation should fail without calling s2n_config_set_custom_critical_oids() */
            {
                .cert_pem_path = S2N_MULTIPLE_OIDS_CERT_CHAIN,
                .key_pem_path = S2N_MULTIPLE_OID_KEY,
                .custom_critical_oids = multiple_oids,
                .custom_oid_count = multiple_oid_count,
                .set_oids = false,
                .expected_error = S2N_ERR_CERT_UNTRUSTED,
            },

            /* Validation should fail with misconfigured custom extensions */
            {
                .cert_pem_path = S2N_MULTIPLE_OIDS_CERT_CHAIN,
                .key_pem_path = S2N_MULTIPLE_OID_KEY,
                .custom_critical_oids = single_oid,
                .custom_oid_count = 1,
                .set_oids = true,
                .expected_error = S2N_ERR_CERT_UNTRUSTED,
            },
        };
        /* clang-format on */

        /* Self-talk: add custom critical extensions for server auth */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    test_cases[i].cert_pem_path, test_cases[i].key_pem_path));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, test_cases[i].cert_pem_path, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            const char **custom_oids = test_cases[i].custom_critical_oids;
            uint32_t custom_oid_count = test_cases[i].custom_oid_count;

            EXPECT_NULL(config->custom_crit_oids);
            if (test_cases[i].set_oids) {
                EXPECT_SUCCESS(s2n_config_set_custom_critical_oids(config, custom_oids, custom_oid_count));
                EXPECT_EQUAL(sk_ASN1_OBJECT_num(config->custom_crit_oids), custom_oid_count);
            }

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        expected_error);
            }
        }

        /* Self-talk: add custom critical extensions for client auth */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *default_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&default_chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, test_cases[i].cert_pem_path, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

            const char **custom_oids = test_cases[i].custom_critical_oids;
            uint32_t custom_oid_count = test_cases[i].custom_oid_count;

            EXPECT_NULL(server_config->custom_crit_oids);
            if (test_cases[i].set_oids) {
                EXPECT_SUCCESS(s2n_config_set_custom_critical_oids(server_config, custom_oids, custom_oid_count));
                EXPECT_EQUAL(sk_ASN1_OBJECT_num(server_config->custom_crit_oids), custom_oid_count);
            }

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    test_cases[i].cert_pem_path, test_cases[i].key_pem_path));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        expected_error);
            }
        }
    }

    END_TEST();
}
