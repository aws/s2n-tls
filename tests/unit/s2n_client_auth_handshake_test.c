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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

/* To get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_tls13_handshake.c"

int s2n_test_client_auth_negotiation(struct s2n_config *server_config, struct s2n_config *client_config, struct s2n_cert_chain_and_key *ecdsa_cert, bool no_cert)
{
    /* Set up client and server connections */
    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
    client_conn->x509_validator.skip_cert_validation = 1;
    client_conn->server_protocol_version = S2N_TLS13;
    client_conn->client_protocol_version = S2N_TLS13;
    client_conn->actual_protocol_version = S2N_TLS13;
    client_conn->handshake_params.server_cert_sig_scheme = &s2n_ecdsa_secp256r1_sha256;
    client_conn->handshake_params.client_cert_sig_scheme = &s2n_ecdsa_secp256r1_sha256;
    client_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    if (!no_cert) {
        client_conn->handshake_params.our_chain_and_key = ecdsa_cert;
    }

    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
    server_conn->server_protocol_version = S2N_TLS13;
    server_conn->client_protocol_version = S2N_TLS13;
    server_conn->actual_protocol_version = S2N_TLS13;
    server_conn->handshake_params.server_cert_sig_scheme = &s2n_ecdsa_secp256r1_sha256;
    server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

    if (no_cert) {
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));
    } else {
        server_conn->x509_validator.skip_cert_validation = 1;
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
    }

    /* Create nonblocking pipes */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
    EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

    /* Negotiate handshake */
    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(server_conn));
    EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(client_conn));
    EXPECT_EQUAL(IS_CLIENT_AUTH_NO_CERT(server_conn), no_cert);
    EXPECT_EQUAL(IS_CLIENT_AUTH_NO_CERT(client_conn), no_cert);

    const char *app_data_str = "APPLICATION_DATA";
    EXPECT_EQUAL(strcmp(app_data_str, s2n_connection_get_last_message_name(client_conn)), 0);

    /* Clean up */
    EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));

    return 0;
}

/* Test to verify the explicit ordering of client_auth handshake with and without a client
 * certificate. This includes some pre and post condition checks that pertain to client 
 * authentication between messages.
 */
int s2n_test_client_auth_message_by_message(bool no_cert)
{
    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    struct s2n_config *server_config, *client_config;
    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20190801"));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20190801"));

    char *cert_chain = NULL;
    char *private_key = NULL;
    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *default_cert;
    EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));
    if (!no_cert) {
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, default_cert));
    }

    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
    if (no_cert) {
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));
    } else {
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
        client_conn->x509_validator.skip_cert_validation = 1;
        server_conn->x509_validator.skip_cert_validation = 1;
    }

    struct s2n_stuffer client_to_server = { 0 };
    struct s2n_stuffer server_to_client = { 0 };

    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

    /* Client sends ClientHello */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
    EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

    EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
    EXPECT_EQUAL(server_conn->actual_protocol_version, 0);

    EXPECT_EQUAL(server_conn->handshake.handshake_type, INITIAL);

    /* Server reads ClientHello */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
    EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13); /* Server is now on TLS13 */
    EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT);

    EXPECT_SUCCESS(s2n_conn_set_handshake_type(server_conn));

    /* Server sends ServerHello */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Server sends CCS */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CHANGE_CIPHER_SPEC);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Server sends EncryptedExtensions */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), ENCRYPTED_EXTENSIONS);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Server sends CertificateRequest */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CERT_REQ);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Server sends ServerCert */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CERT);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Server sends CertVerify */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CERT_VERIFY);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Server sends ServerFinished */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_FINISHED);
    EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

    /* Client reads ServerHello */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    /* Client reads CCS
     * The CCS message does not affect its place in the state machine. */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    /* Client reads EncryptedExtensions */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    if (no_cert) {
        /* Client reads CertificateRequest but expects Cert */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT);
    } else {
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT_REQ);
    }
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    EXPECT_EQUAL(client_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT);

    /* Client reads ServerCert */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT);
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    /* Client reads CertVerify */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT_VERIFY);
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    /* Client reads ServerFinished */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_FINISHED);
    EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

    /* Client sends CCS */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_CHANGE_CIPHER_SPEC);
    EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

    /* Client sends ClientCert */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_CERT);
    EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

    if (no_cert) {
        EXPECT_EQUAL(client_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | MIDDLEBOX_COMPAT);
    } else {
        EXPECT_EQUAL(client_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT);

        /* Client sends CertVerify */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_CERT_VERIFY);
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));
    }

    /* Client sends ClientFinished */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_FINISHED);
    EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

    /* Server reads CCS
     * The CCS message does not affect its place in the state machine. */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_CERT);
    EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

    /* Server reads ClientCert */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_CERT);
    EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

    if (no_cert) {
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | MIDDLEBOX_COMPAT);
    } else {
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT);

        /* Server reads CertVerify */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_CERT_VERIFY);
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));
    }

    /* Server reads ClientFinished */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_FINISHED);
    EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

    EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
    EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

    /* Clean up */
    EXPECT_SUCCESS(s2n_stuffer_free(&client_to_server));
    EXPECT_SUCCESS(s2n_stuffer_free(&server_to_client));

    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_connection_free(server_conn));

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(default_cert));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_config_free(client_config));

    free(private_key);
    free(cert_chain);

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* client_auth handshake negotiation */
    {
        struct s2n_config *server_config, *client_config;
        uint8_t *cert_chain_pem = NULL;
        uint8_t *private_key_pem = NULL;
        uint32_t cert_chain_len = 0;
        uint32_t private_key_len = 0;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20190801"));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20190801"));

        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, &private_key_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(ecdsa_cert, cert_chain_pem, cert_chain_len, private_key_pem, private_key_len));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));

        /* client_auth with no cert */
        EXPECT_SUCCESS(s2n_test_client_auth_negotiation(server_config, client_config, ecdsa_cert, 1));

        /* client_auth with cert */
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_test_client_auth_negotiation(server_config, client_config, ecdsa_cert, 0));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        free(cert_chain_pem);
        free(private_key_pem);
    };

    /* Test each message is sent and in the correct order */
    {
        /* Test messsage by message with no cert */
        s2n_test_client_auth_message_by_message(1);

        /* Test message by message with a cert */
        s2n_test_client_auth_message_by_message(0);
    };

    END_TEST();
}
