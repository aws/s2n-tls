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
#include "utils/s2n_random.h"

#define S2N_TEST_DATA_SIZE 100

S2N_RESULT s2n_test_send_receive_data(struct s2n_connection *sender, struct s2n_connection *receiver)
{
    uint8_t test_data[S2N_TEST_DATA_SIZE] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Send data */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    ssize_t bytes_written = 0;
    while (bytes_written < S2N_TEST_DATA_SIZE) {
        ssize_t w = s2n_send(sender, test_data + bytes_written, S2N_TEST_DATA_SIZE - bytes_written, &blocked);
        EXPECT_TRUE(w >= 0);
        bytes_written += w;
    }

    /* Receive data */
    uint8_t buffer[S2N_TEST_DATA_SIZE] = { 0 };
    ssize_t bytes_received = 0;
    while (bytes_received < S2N_TEST_DATA_SIZE) {
        ssize_t r = s2n_recv(receiver, buffer + bytes_received, S2N_TEST_DATA_SIZE - bytes_received, &blocked);
        EXPECT_TRUE(r > 0);
        bytes_received += r;
    }

    EXPECT_BYTEARRAY_EQUAL(test_data, buffer, S2N_TEST_DATA_SIZE);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_hmac_is_available(S2N_HMAC_SSLv3_MD5)) {
        /* AWS-LC should support SSLv3. */
        EXPECT_FALSE(s2n_libcrypto_is_awslc());

        /* Other libcryptos may not support SSLv3, so the tests are skipped. */
        END_TEST();
    }

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    /* Self-talk test */
    {
        size_t supported_record_alg_count = 0;

        for (size_t i = 0; i < security_policy_test_all.cipher_preferences->count; i++) {
            struct s2n_cipher_suite *cipher_suite = security_policy_test_all.cipher_preferences->suites[i];

            /* Skip non-sslv3 cipher suites. */
            if (!cipher_suite->sslv3_record_alg) {
                continue;
            }

            /* Skip unsupported record algorithms. */
            if (!cipher_suite->sslv3_record_alg->cipher->is_available()) {
                continue;
            }
            supported_record_alg_count += 1;

            struct s2n_cipher_preferences test_cipher_preferences = {
                .count = 1,
                .suites = &cipher_suite,
            };
            struct s2n_security_policy test_policy = security_policy_test_all;
            test_policy.cipher_preferences = &test_cipher_preferences;

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
            client_config->security_policy = &test_policy;

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            server_config->security_policy = &test_policy;

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            client->client_protocol_version = S2N_SSLv3;

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), S2N_SSLv3);
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server), S2N_SSLv3);

            EXPECT_OK(s2n_test_send_receive_data(client, server));
            EXPECT_OK(s2n_test_send_receive_data(server, client));
        }

        /* Ensure that a supported record algorithm was found, and SSLv3 was tested at least once. */
        EXPECT_TRUE(supported_record_alg_count > 0);
    }

    END_TEST();
}
