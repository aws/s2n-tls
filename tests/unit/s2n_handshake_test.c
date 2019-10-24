/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && errno == EAGAIN))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && errno == EAGAIN) || server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT)) {
            return -1;
        }

        tries += 1;
        if (tries == 5) {
            return -1;
        }
    } while (client_blocked || server_blocked);

    uint8_t server_shutdown = 0;
    uint8_t client_shutdown = 0;
    do {
        if (!server_shutdown) {
            int server_rc = s2n_shutdown(server_conn, &server_blocked);
            if (server_rc == 0) {
                server_shutdown = 1;
            } else if (!(server_blocked && errno == EAGAIN)) {
                return -1;
            }
        }

        if (!client_shutdown) {
            int client_rc = s2n_shutdown(client_conn, &client_blocked);
            if (client_rc == 0) {
                client_shutdown = 1;
            } else if (!(client_blocked && errno == EAGAIN)) {
                return -1;
            }
        }
    } while (!server_shutdown || !client_shutdown);

    return 0;
}

int test_cipher_preferences(struct s2n_config *server_config, struct s2n_config *client_config) {
    const struct s2n_cipher_preferences *cipher_preferences;

    cipher_preferences = server_config->cipher_preferences;
    notnull_check(cipher_preferences);

    if (s2n_is_in_fips_mode()) {
        /* Override default client config ciphers when in FIPS mode to ensure all FIPS
         * default ciphers are tested.
         */
        client_config->cipher_preferences = cipher_preferences;
        notnull_check(client_config->cipher_preferences);
    }

    /* Verify that a handshake succeeds for every available cipher in the default list. For unavailable ciphers,
     * make sure that we fail the handshake. */
    for (int cipher_idx = 0; cipher_idx < cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        server_conn = s2n_connection_new(S2N_SERVER);
        notnull_check(server_conn);
        int server_to_client[2];
        int client_to_server[2];
        struct s2n_cipher_suite *expected_cipher = cipher_preferences->suites[cipher_idx];
        uint8_t expect_failure = 0;

        /* Expect failure if the libcrypto we're building with can't support the cipher */
        if (!expected_cipher->available) {
            expect_failure = 1;
        }

        /* Craft a cipher preference with a cipher_idx cipher
           NOTE: Its safe to use memcpy as the address of server_cipher_preferences
           will never be NULL */
        memcpy(&server_cipher_preferences, cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        server_cipher_preferences.suites = &expected_cipher;
        server_conn->cipher_pref_override = &server_cipher_preferences;

        /* Create nonblocking pipes */
        GUARD(pipe(server_to_client));
        GUARD(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           ne_check(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           ne_check(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        client_conn = s2n_connection_new(S2N_CLIENT);
        notnull_check(client_conn);
        GUARD(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        GUARD(s2n_connection_set_write_fd(client_conn, client_to_server[1]));
        GUARD(s2n_connection_set_config(client_conn, client_config));
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        client_conn->actual_protocol_version = S2N_TLS12;

        GUARD(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        GUARD(s2n_connection_set_write_fd(server_conn, server_to_client[1]));
        GUARD(s2n_connection_set_config(server_conn, server_config));
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        server_conn->actual_protocol_version = S2N_TLS12;

        const char* app_data_str = "APPLICATION_DATA";
        if (!expect_failure) {
            GUARD(try_handshake(server_conn, client_conn));
            const char* actual_cipher = s2n_connection_get_cipher(server_conn);
            if (strcmp(actual_cipher, expected_cipher->name) != 0){
                return -1;
            }

            const char *handshake_type_name = s2n_connection_get_handshake_type_name(client_conn);
            if (NULL == strstr(handshake_type_name, "NEGOTIATED|FULL_HANDSHAKE")) {
                return -1;
            }

            /* Calling the same funciton on the same connection again should get the same handshake name */
            if (strcmp(s2n_connection_get_handshake_type_name(client_conn), handshake_type_name) != 0) {
                return -1;
            }

            handshake_type_name = s2n_connection_get_handshake_type_name(server_conn);
            if (NULL == strstr(handshake_type_name, "NEGOTIATED|FULL_HANDSHAKE")) {
                return -1;
            }

            if (strcmp(s2n_connection_get_handshake_type_name(server_conn), handshake_type_name) != 0) {
                return -1;
            }

            if (strcmp(app_data_str, s2n_connection_get_last_message_name(client_conn)) != 0 ||
                strcmp(app_data_str, s2n_connection_get_last_message_name(server_conn)) != 0) {
                return -1;
            }
        } else {
            eq_check(try_handshake(server_conn, client_conn), -1);
            if (0 == strcmp(app_data_str, s2n_connection_get_last_message_name(client_conn)) ||
                0 == strcmp(app_data_str, s2n_connection_get_last_message_name(server_conn))) {
                return -1;
            }
        }

        GUARD(s2n_connection_free(server_conn));
        GUARD(s2n_connection_free(client_conn));

        for (int i = 0; i < 2; i++) {
           GUARD(close(server_to_client[i]));
           GUARD(close(client_to_server[i]));
        }
    }

    return 0;
}

int main(int argc, char **argv)
{

    BEGIN_TEST();

    /*  test_with_rsa_cert(); */
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        char *dhparams_pem;
        struct s2n_cert_chain_and_key *chain_and_key;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
    
        client_config = s2n_fetch_unsafe_client_testing_config();
        
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);

    }

    /*  test_with_ecdsa_cert() */
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        char *dhparams_pem;
        struct s2n_cert_chain_and_key *chain_and_key;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_ecdsa"));

        EXPECT_NOT_NULL(client_config = s2n_fetch_unsafe_client_ecdsa_testing_config());

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));
        
        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);

    }

    END_TEST();
    return 0;
}

