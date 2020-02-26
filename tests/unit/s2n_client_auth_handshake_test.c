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
#include "tls/s2n_tls13.h"

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

/* TODO: replace the below function with calls to:
int s2n_negotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn);
int s2n_shutdown_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn);
*/

static int s2n_try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
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

/*TODO: update pipe logic to use new functions after rebase */
int s2n_test_client_auth(struct s2n_config *server_config, struct s2n_config *client_config, bool no_cert)
{
    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;
    server_conn = s2n_connection_new(S2N_SERVER);
    notnull_check(server_conn);
    int server_to_client[2];
    int client_to_server[2];

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
    client_conn->x509_validator.skip_cert_validation = 1;
    client_conn->server_protocol_version = S2N_TLS13;
    client_conn->client_protocol_version = S2N_TLS13;
    client_conn->actual_protocol_version = S2N_TLS13;

    GUARD(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
    GUARD(s2n_connection_set_write_fd(server_conn, server_to_client[1]));
    GUARD(s2n_connection_set_config(server_conn, server_config));
    server_conn->server_protocol_version = S2N_TLS13;
    server_conn->client_protocol_version = S2N_TLS13;
    server_conn->actual_protocol_version = S2N_TLS13;

    server_conn->secure.conn_sig_scheme = s2n_ecdsa_secp256r1_sha256;
    client_conn->secure.conn_sig_scheme = s2n_ecdsa_secp256r1_sha256;
    server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

    if (no_cert) {
        s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL);
        s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL);
    } else {
        server_conn->x509_validator.skip_cert_validation = 1;
        s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED);
        s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED);
    }

    GUARD(s2n_try_handshake(server_conn, client_conn));

    GUARD(IS_CLIENT_AUTH_HANDSHAKE(server_conn->handshake.handshake_type));
    GUARD(IS_CLIENT_AUTH_HANDSHAKE(client_conn->handshake.handshake_type));

    GUARD(IS_CLIENT_AUTH_NO_CERT(server_conn->handshake.handshake_type) == no_cert);
    GUARD(IS_CLIENT_AUTH_NO_CERT(client_conn->handshake.handshake_type) == no_cert);

    const char *app_data_str = "APPLICATION_DATA";
    if(strcmp(app_data_str, s2n_connection_get_last_message_name(client_conn)) != 0) {
        return -1;
    }

    /* Clean up */
    GUARD(s2n_connection_free(server_conn));
    GUARD(s2n_connection_free(client_conn));

    for (int i = 0; i < 2; i++) {
       GUARD(close(server_to_client[i]));
       GUARD(close(client_to_server[i]));
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* client_auth handshake with no cert*/
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_signature_preferences(server_config, "20200207"));
        EXPECT_SUCCESS(s2n_config_set_signature_preferences(client_config, "20200207"));

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(s2n_test_client_auth(server_config, client_config, 1));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(private_key_pem);
    }

    /* client_auth handshake with cert */
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_config_set_signature_preferences(server_config, "20200207"));
        EXPECT_SUCCESS(s2n_config_set_signature_preferences(client_config, "20200207"));
        EXPECT_SUCCESS(s2n_test_client_auth(server_config, client_config, 0));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(private_key_pem);
    }

    /* client_auth no cert handshake low-level test */

    /* client auth with cert handshake low-level test */

    END_TEST();
}
