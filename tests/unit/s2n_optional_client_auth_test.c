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
#include <s2n.h>

#include <stdlib.h>
#include <fcntl.h>

#include "testlib/s2n_testlib.h"

#include "crypto/s2n_fips.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"

static const int MAX_TRIES = 100;

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    int tries = 0;
    s2n_blocked_status client_blocked;
    s2n_blocked_status server_blocked;
    do {
        int rc;
        rc = s2n_negotiate(client_conn, &client_blocked);
        if (rc != 0 && (client_blocked && errno != EAGAIN)) {
            return -1;
        }
        rc = s2n_negotiate(server_conn, &server_blocked);
        if (rc != 0 && (server_blocked && errno != EAGAIN)) {
            return -1;
        }

        tries += 1;
        if (tries >= MAX_TRIES) {
            return -1;
        }
    } while (client_blocked || server_blocked);
    return 0;
}

int main(int argc, char **argv)
{
    struct s2n_config *client_config;
    struct s2n_config *server_config;
    const struct s2n_cipher_preferences *default_cipher_preferences;
    char *cert_chain_pem;
    char *private_key_pem;
    char *dhparams_pem;
    struct s2n_cert_chain_and_key *chain_and_key;

    BEGIN_TEST();

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    /* Setup baseline server config and certs. */
    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
    EXPECT_NOT_NULL(default_cipher_preferences = server_config->cipher_preferences);


    /*
     * Test optional client auth using **s2n_config_set_client_auth_type** with a valid client cert provided.
     */

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

    /* Server requires optional client auth and accepts the client cert. */
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_OPTIONAL));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(server_config));

    /* Verify that a handshake succeeds for every cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int client_to_server[2];
        int server_to_client[2];

        /* Craft a cipher preference with a cipher_idx cipher. */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];

        if (!cur_cipher->available) {
            /* Skip ciphers that aren't supported with the linked libcrypto. */
            continue;
        }

        server_cipher_preferences.suites = &cur_cipher;
        client_config->cipher_preferences = &server_cipher_preferences;
        server_config->cipher_preferences = &server_cipher_preferences;

        /* Create nonblocking pipes. */
        EXPECT_SUCCESS(pipe(client_to_server));
        EXPECT_SUCCESS(pipe(server_to_client));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        /* Verify the handshake was successful. */
        EXPECT_SUCCESS(try_handshake(server_conn, client_conn));

        /* Verify that both connections negotiated mutual auth. */
        EXPECT_TRUE(s2n_connection_client_cert_used(server_conn));
        EXPECT_TRUE(s2n_connection_client_cert_used(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(client_config));

    /*
     * Test optional client auth using **s2n_config_set_client_auth_type** with S2N_CERT_AUTH_NONE for Server
     */

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

    /* Server does not request a Client Cert. */
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_NONE));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(server_config));

    /* Verify that a handshake succeeds for every cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int client_to_server[2];
        int server_to_client[2];

        /* Craft a cipher preference with a cipher_idx cipher. */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];

        if (!cur_cipher->available) {
            /* Skip ciphers that aren't supported with the linked libcrypto. */
            continue;
        }

        server_cipher_preferences.suites = &cur_cipher;
        client_config->cipher_preferences = &server_cipher_preferences;
        server_config->cipher_preferences = &server_cipher_preferences;

        /* Create nonblocking pipes. */
        EXPECT_SUCCESS(pipe(client_to_server));
        EXPECT_SUCCESS(pipe(server_to_client));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        /* Verify the handshake was successful. */
        EXPECT_SUCCESS(try_handshake(server_conn, client_conn));

        /* Verify that neither connections negotiated mutual auth. */
        EXPECT_FALSE(s2n_connection_client_cert_used(server_conn));
        EXPECT_FALSE(s2n_connection_client_cert_used(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(client_config));


    /*
     * Test optional client auth using **s2n_config_set_client_auth_type** with no client cert provided.
     */

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

    /* Server requires optional client auth and accepts the client cert. */
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_OPTIONAL));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(server_config));

    /* Verify that a handshake succeeds for every cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int client_to_server[2];
        int server_to_client[2];

        /* Craft a cipher preference with a cipher_idx cipher. */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];

        if (!cur_cipher->available) {
            /* Skip ciphers that aren't supported with the linked libcrypto. */
            continue;
        }

        server_cipher_preferences.suites = &cur_cipher;
        client_config->cipher_preferences = &server_cipher_preferences;
        server_config->cipher_preferences = &server_cipher_preferences;

        /* Create nonblocking pipes. */
        EXPECT_SUCCESS(pipe(client_to_server));
        EXPECT_SUCCESS(pipe(server_to_client));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        /* Verify the handshake was successful. */
        EXPECT_SUCCESS(try_handshake(server_conn, client_conn));

        /* Verify that neither connection negotiated mutual auth. */
        EXPECT_FALSE(s2n_connection_client_cert_used(server_conn));
        EXPECT_FALSE(s2n_connection_client_cert_used(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }
    
    EXPECT_SUCCESS(s2n_config_free(client_config));


    /*
     * Test optional client auth using **s2n_connection_set_client_auth_type** with a valid client cert provided.
     */

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));

    /* Server requires no client auth but the connection will. */
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_NONE));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(server_config));

    /* Verify that a handshake succeeds for every cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int client_to_server[2];
        int server_to_client[2];

        /* Craft a cipher preference with a cipher_idx cipher. */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];

        if (!cur_cipher->available) {
            /* Skip ciphers that aren't supported with the linked libcrypto. */
            continue;
        }

        server_cipher_preferences.suites = &cur_cipher;
        client_config->cipher_preferences = &server_cipher_preferences;
        server_config->cipher_preferences = &server_cipher_preferences;

        /* Create nonblocking pipes. */
        EXPECT_SUCCESS(pipe(client_to_server));
        EXPECT_SUCCESS(pipe(server_to_client));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Override the config setting on the connection. */
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        /* Override the config setting on the connection. */
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL));

        /* Verify the handshake was successful. */
        EXPECT_SUCCESS(try_handshake(server_conn, client_conn));

        /* Verify that both connections negotiated mutual auth. */
        EXPECT_TRUE(s2n_connection_client_cert_used(server_conn));
        EXPECT_TRUE(s2n_connection_client_cert_used(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(client_config));


    /*
     * Test optional client auth using **s2n_connection_set_client_auth_type** with no client cert provided.
     */

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));

    /* Server requires client auth but the connection will allow an empty client cert. */
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(server_config));

    /* Verify that a handshake succeeds for every cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int client_to_server[2];
        int server_to_client[2];

        /* Craft a cipher preference with a cipher_idx cipher. */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];

        if (!cur_cipher->available) {
            /* Skip ciphers that aren't supported with the linked libcrypto. */
            continue;
        }

        server_cipher_preferences.suites = &cur_cipher;
        client_config->cipher_preferences = &server_cipher_preferences;
        server_config->cipher_preferences = &server_cipher_preferences;

        /* Create nonblocking pipes. */
        EXPECT_SUCCESS(pipe(client_to_server));
        EXPECT_SUCCESS(pipe(server_to_client));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Override the config setting on the connection. */
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        /* Override the config setting on the connection. */
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL));

        /* Verify the handshake was successful. */
        EXPECT_SUCCESS(try_handshake(server_conn, client_conn));

        /* Verify that neither connection negotiated mutual auth. */
        EXPECT_FALSE(s2n_connection_client_cert_used(server_conn));
        EXPECT_FALSE(s2n_connection_client_cert_used(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(client_config));


    /*
     * Test optional client auth using **s2n_config_set_client_auth_type** with an incorrect client
     * cert provided fails negotiation, allowing the user to fatally kill the handshake if they want.
     * https://tools.ietf.org/html/rfc5246#section-7.4.6
     */

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

    /* Server requires optional client auth but will reject the client cert. We need to reset the config, to turn validation back on*/
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
    EXPECT_NOT_NULL(default_cipher_preferences = server_config->cipher_preferences);
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_OPTIONAL));

    /* Verify that a handshake fails for every cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int client_to_server[2];
        int server_to_client[2];

        /* Craft a cipher preference with a cipher_idx cipher. */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];

        if (!cur_cipher->available) {
            /* Skip ciphers that aren't supported with the linked libcrypto. */
            continue;
        }

        server_cipher_preferences.suites = &cur_cipher;
        client_config->cipher_preferences = &server_cipher_preferences;
        server_config->cipher_preferences = &server_cipher_preferences;

        /* Create nonblocking pipes. */
        EXPECT_SUCCESS(pipe(client_to_server));
        EXPECT_SUCCESS(pipe(server_to_client));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        /* Verify the handshake failed. Blinding is disabled for the failure case to speed up tests. */
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_FAILURE(try_handshake(server_conn, client_conn));

        /* Verify that neither connection negotiated mutual auth. */
        EXPECT_FALSE(s2n_connection_client_cert_used(server_conn));
        EXPECT_FALSE(s2n_connection_client_cert_used(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }
    
    EXPECT_SUCCESS(s2n_config_free(client_config));

    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);
    END_TEST();
    return 0;
}
