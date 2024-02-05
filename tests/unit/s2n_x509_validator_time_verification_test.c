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

bool s2n_libcrypto_supports_flag_no_check_time();
uint64_t s2n_libcrypto_awslc_api_version(void);

static uint8_t s2n_verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Test the NO_CHECK_TIME flag feature probe. The flag was added to AWS-LC in API version 19. */
    if (s2n_libcrypto_is_awslc() && s2n_libcrypto_awslc_api_version() > 19) {
        EXPECT_TRUE(s2n_libcrypto_supports_flag_no_check_time());
    }

    /* Test disabling x509 time validation.
     *
     * By default, validation should fail for certificates with invalid timestamps. However, if
     * x509 time validation is disabled, validation should succeed.
     *
     * When time validation is disabled, s2n_config_set_wall_clock() will not set a custom time on
     * the libcrypto, so this function cannot be used to set a fake time for testing. Instead, the
     * test certificates themselves contain invalid timestamps.
     */
    {
        /* clang-format off */
        struct {
            const char *cert_pem_path;
            const char *key_pem_path;
            bool disable_x509_time_validation;
            s2n_error expected_error;
        } test_cases[] = {
            /* Validation should fail for a certificate that is not yet valid. */
            {
                .cert_pem_path = S2N_NOT_YET_VALID_CERT_CHAIN,
                .key_pem_path = S2N_NOT_YET_VALID_KEY,
                .disable_x509_time_validation = false,
                .expected_error = S2N_ERR_CERT_NOT_YET_VALID,
            },

            /* Validation should succeed for a certificate that is not yet valid when time
             * validation is disabled.
             */
            {
                .cert_pem_path = S2N_NOT_YET_VALID_CERT_CHAIN,
                .key_pem_path = S2N_NOT_YET_VALID_KEY,
                .disable_x509_time_validation = true,
                .expected_error = S2N_ERR_OK,
            },

            /* Validation should fail for an expired certificate. */
            {
                .cert_pem_path = S2N_EXPIRED_CERT_CHAIN,
                .key_pem_path = S2N_EXPIRED_KEY,
                .disable_x509_time_validation = false,
                .expected_error = S2N_ERR_CERT_EXPIRED,
            },

            /* Validation should succeed for an expired certificate when time validation is
             * disabled.
             */
            {
                .cert_pem_path = S2N_EXPIRED_CERT_CHAIN,
                .key_pem_path = S2N_EXPIRED_KEY,
                .disable_x509_time_validation = true,
                .expected_error = S2N_ERR_OK,
            },
        };
        /* clang-format on */

        /* s2n_x509_validator test */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
            s2n_x509_trust_store_init_empty(&trust_store);

            char cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_read_test_pem(test_cases[i].cert_pem_path, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, cert_chain));

            DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            if (test_cases[i].disable_x509_time_validation) {
                EXPECT_SUCCESS(s2n_config_disable_x509_time_verification(config));
            }

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_set_server_name(conn, "localhost"));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, test_cases[i].cert_pem_path, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

            s2n_result ret = s2n_x509_validator_validate_cert_chain(&validator, conn, chain_data, chain_len, &pkey_type,
                    &public_key_out);

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_OK(ret);
            } else {
                EXPECT_ERROR_WITH_ERRNO(ret, expected_error);
            }
        }

        /* Self-talk: Disable validity period validation on client for server auth */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    test_cases[i].cert_pem_path, test_cases[i].key_pem_path));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, test_cases[i].cert_pem_path, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            if (test_cases[i].disable_x509_time_validation) {
                EXPECT_SUCCESS(s2n_config_disable_x509_time_verification(config));
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

            int ret = s2n_negotiate_test_server_and_client(server_conn, client_conn);

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(ret);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(ret, expected_error);
            }
        }

        /* Self-talk: Disable validity period validation on server for client auth */
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

            if (test_cases[i].disable_x509_time_validation) {
                EXPECT_SUCCESS(s2n_config_disable_x509_time_verification(server_config));
            }

            /* Disable verify host validation for client auth */
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(server_config, s2n_verify_host_accept_everything, NULL));

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
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            int ret = s2n_negotiate_test_server_and_client(server_conn, client_conn);

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(ret);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(ret, expected_error);
            }
        }
    }

    /* Ensure that certificate validation can fail for reasons other than time validation when time
     * validation is disabled.
     */
    for (int trust_cert = 0; trust_cert <= 1; trust_cert += 1) {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        if (trust_cert) {
            char cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, cert_chain));
        }

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_config_disable_x509_time_verification(config));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(conn, "s2nTestServer"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        s2n_result ret = s2n_x509_validator_validate_cert_chain(&validator, conn, chain_data, chain_len, &pkey_type,
                &public_key_out);

        if (trust_cert) {
            EXPECT_OK(ret);
        } else {
            /* If the certificate was not added to the trust store, validation should fail even
             * though time validation was disabled.
             */
            EXPECT_ERROR_WITH_ERRNO(ret, S2N_ERR_CERT_UNTRUSTED);
        }
    }

    END_TEST();
}
