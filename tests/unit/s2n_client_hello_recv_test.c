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
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_sslv2_client_hello.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    struct s2n_connection *server_conn;
    struct s2n_connection *client_conn;
    struct s2n_stuffer *hello_stuffer;
    struct s2n_config *tls12_config;
    struct s2n_config *tls13_config;
    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_cert_chain_and_key *tls13_chain_and_key;
    char *cert_chain;
    char *tls13_cert_chain;
    char *private_key;
    char *tls13_private_key;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(tls12_config = s2n_config_new());
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls12_config, "test_all_tls12"));

    EXPECT_NOT_NULL(tls13_cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(tls13_private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(tls13_config = s2n_config_new());
    EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls13_config, "test_all"));

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls12_config, chain_and_key));

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls13_config, tls13_chain_and_key));

    /* These tests verify the logic behind the setting of these three connection fields:
    server_protocol_version, client_protocol_version, and actual_protocol version. */

    /* Test we can successfully receive an sslv2 client hello and set a
     * tls12 connection */
    for (uint8_t i = 0; i < 2; i++) {
        if (i == 1) {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        }

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));

        /* Record version and protocol version are in the header for SSLv2 */
        server_conn->client_hello_version = S2N_SSLv2;
        server_conn->client_protocol_version = S2N_TLS12;

        uint8_t sslv2_client_hello[] = {
            SSLv2_CLIENT_HELLO_PREFIX,
            SSLv2_CLIENT_HELLO_CIPHER_SUITES,
            SSLv2_CLIENT_HELLO_CHALLENGE,
        };

        struct s2n_blob client_hello = {
            .data = sslv2_client_hello,
            .size = sizeof(sslv2_client_hello),
            .allocated = 0,
            .growable = 0
        };
        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_hello));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, i == 0 ? S2N_TLS12 : S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_SSLv2);
        EXPECT_EQUAL(server_conn->client_hello.callback_invoked, 1);

        s2n_connection_free(server_conn);

        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    }

    /* Test that a tls12 client legacy version and tls12 server version
    will successfully set a tls12 connection, since tls13 is not enabled. */
    {
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_conn->handshake.io.blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
    };

    /* Test that a tls12 client legacy version and tls12 server version
    will successfully set a tls12 connection, even when tls13 is enabled. */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_conn->handshake.io.blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* Test that a tls11 client legacy version and tls12 server version
    will successfully set a tls11 connection. */
    for (uint8_t i = 0; i < 2; i++) {
        if (i == 1) {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        }

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));

        client_conn->client_protocol_version = S2N_TLS11;

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS11);

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_conn->handshake.io.blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS11);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS11);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS11);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);

        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    }
    /* Test that a tls12 client and tls13 server will successfully
    set a tls12 connection. */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));

        EXPECT_SUCCESS(s2n_enable_tls13_in_test());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_EQUAL(client_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_conn->handshake.io.blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };
    /* Test that an erroneous client legacy version and tls13 server version
    will still successfully set a tls13 connection, when real client version is tls13. */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        hello_stuffer = &client_conn->handshake.io;

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        /* Overwrite the client legacy version so that it reads tls13 (incorrectly) */
        uint8_t incorrect_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
        incorrect_protocol_version[0] = S2N_TLS13 / 10;
        incorrect_protocol_version[1] = S2N_TLS13 % 10;
        EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(hello_stuffer, incorrect_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &hello_stuffer->blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(client_conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(client_conn->client_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS12);

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(server_conn->client_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* Test that a tls12 client legacy version and tls13 server version
    will still successfully set a tls13 connection, if possible. */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_conn->handshake.io.blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(server_conn->client_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };
    /* Test that an erroneous(tls13) client legacy version and tls13 server version
    will still successfully set a tls12 connection, if tls12 is the true client version. */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        hello_stuffer = &client_conn->handshake.io;

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        /* Overwrite the client legacy version so that it reads tls13 (incorrectly) */
        uint8_t incorrect_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
        incorrect_protocol_version[0] = S2N_TLS13 / 10;
        incorrect_protocol_version[1] = S2N_TLS13 % 10;
        EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(hello_stuffer, incorrect_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &hello_stuffer->blob));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->server_protocol_version, s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* s2n receiving a client hello will error when parsing an empty cipher suite */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));

        hello_stuffer = &client_conn->handshake.io;

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        uint8_t empty_cipher_suite[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };

        /* Move write_cursor to cipher_suite position */
        EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(hello_stuffer, S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN + 1));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(hello_stuffer, empty_cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &hello_stuffer->blob));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_recv(server_conn), S2N_ERR_BAD_MESSAGE);

        s2n_connection_free(server_conn);
        s2n_connection_free(client_conn);
    };

    /* s2n receiving a sslv2 client hello will error when parsing an empty cipher suite */
    {
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));

        /* Record version and protocol version are in the header for SSLv2 */
        server_conn->client_hello_version = S2N_SSLv2;
        server_conn->client_protocol_version = S2N_TLS12;

        /* Writing a sslv2 client hello with a length 0 cipher suite list */
        uint8_t sslv2_client_hello[] = {
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x20,
            SSLv2_CLIENT_HELLO_CIPHER_SUITES,
            SSLv2_CLIENT_HELLO_CHALLENGE,
        };

        struct s2n_blob client_hello = {
            .data = sslv2_client_hello,
            .size = sizeof(sslv2_client_hello),
            .allocated = 0,
            .growable = 0
        };
        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_hello));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_recv(server_conn), S2N_ERR_BAD_MESSAGE);

        s2n_connection_free(server_conn);
    };

    /* Test that S2N will accept a ClientHello with legacy_session_id set when running with QUIC.
     * Since this requirement is a SHOULD, we're accepting it for non-compliant endpoints.
     * https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.4*/
    if (s2n_is_tls13_fully_supported()) {
        EXPECT_SUCCESS(s2n_reset_tls13_in_test());

        const size_t test_session_id_len = 10;

        struct s2n_config *quic_config;
        EXPECT_NOT_NULL(quic_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_enable_quic(quic_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(quic_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(quic_config, "default_tls13"));

        /* Succeeds without a session id */
        {
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, quic_config));

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, quic_config));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            s2n_connection_free(client_conn);
            s2n_connection_free(server_conn);
        };

        /* Also, succeeds with a session id */
        {
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, quic_config));

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, quic_config));

            /* Directly set session id, which is not set by default when using QUIC */
            client_conn->session_id_len = test_session_id_len;

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            s2n_connection_free(client_conn);
            s2n_connection_free(server_conn);
        };

        s2n_config_free(quic_config);
    }

    /* Test that the server will not choose a signature algorithm or certificate if using PSKs */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));

        struct s2n_psk chosen_psk = { 0 };
        chosen_psk.hmac_alg = S2N_HMAC_SHA256;
        server_conn->psk_params.chosen_psk = &chosen_psk;
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_EQUAL(server_conn->handshake_params.server_cert_sig_scheme->iana_value, 0);
        EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test that curve selection will be NIST P-256 when tls12 client does not send curve extension.
     *
     *= https://tools.ietf.org/rfc/rfc4492#section-4
     *= type=test
     *# A client that proposes ECC cipher suites may choose not to include these extensions.
     *# In this case, the server is free to choose any one of the elliptic curves or point formats listed in Section 5.
     */
    {
        S2N_BLOB_FROM_HEX(tls12_client_hello_no_curves,
                /* clang-format off */
                "030307de81928fe1" "7cba77904c2798da" "2521a76b013a16e4" "21ade32208f658d4" "327d000048000400"
                "05000a0016002f00" "3300350039003c00" "3d0067006b009c00" "9d009e009fc009c0" "0ac011c012c013c0"
                "14c023c024c027c0" "28c02bc02cc02fc0" "30cca8cca9ccaaff" "04ff0800ff010000" "30000d0016001404"
                "0105010601030104" "0305030603030302" "010203000b000201" "00fe01000c000a00" "17000d0013000100"
                "0a" /* clang-format on */);

        /* The above code is generated the following code,
            disabling s2n_client_supported_groups_extension
            from client_hello_extensions (s2n_extension_type_lists.c)
            and exporting the resulting client_conn->handshake.io.blob

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_EQUAL(client_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS12);
        s2n_connection_free(client_conn);
        */

        EXPECT_SUCCESS(s2n_enable_tls13_in_test());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &tls12_client_hello_no_curves));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* ensure negotiated_curve == secp256r1 for maximum client compatibility */
        EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, &s2n_ecc_curve_secp256r1);

        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

        s2n_connection_free(server_conn);
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    s2n_config_free(tls12_config);
    s2n_config_free(tls13_config);
    s2n_cert_chain_and_key_free(chain_and_key);
    free(cert_chain);
    free(private_key);
    s2n_cert_chain_and_key_free(tls13_chain_and_key);
    free(tls13_cert_chain);
    free(tls13_private_key);
    END_TEST();
    return 0;
}
