/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_cipher_preferences.h"

#include "utils/s2n_safety.h"

const uint8_t EXTENSION_LEN = 2;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_server_extensions_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        /* Test Server Extensions Send - No extensions */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Server Name */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 4 + EXTENSION_LEN);

            conn->server_name_used = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Application Protocol */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            strcpy(conn->application_protocol, "h2");
            const uint8_t application_protocol_len = strlen(conn->application_protocol);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            const uint8_t ALPN_LEN = 7 + application_protocol_len;
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, ALPN_LEN + EXTENSION_LEN);

            strcpy(conn->application_protocol, "");
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Secure Negotiation */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure_renegotiation = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            const uint8_t SECURE_RENEGOTIATION_SIZE = 5;
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, SECURE_RENEGOTIATION_SIZE + EXTENSION_LEN);

            conn->secure_renegotiation = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS13 Extensions */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure.server_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];

            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->secure.client_ecc_params[0].negotiated_curve = &s2n_ecc_supported_curves[0];

            uint8_t size = s2n_extensions_server_key_share_send_size(conn)
                + s2n_extensions_server_supported_versions_size()
                + EXTENSION_LEN;

            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&conn->secure.client_ecc_params[0]));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size);

            /* Test that s2n_server_extensions_send() do not send extension < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS13 Extensions with null key exchange alg cipher suites */
        {
            struct s2n_cipher_suite *tls12_cipher_suite = cipher_preferences_20170210.suites[cipher_preferences_20170210.count-1];
            uint8_t wire_ciphers_with_tls13[] = {
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                tls12_cipher_suite->iana_value[0], tls12_cipher_suite->iana_value[1]
            };
            const uint8_t cipher_count_tls13 = sizeof(wire_ciphers_with_tls13) / S2N_TLS_CIPHER_SUITE_LEN;

            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure.server_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];

            s2n_connection_set_cipher_preferences(conn, "test_tls13_null_key_exchange_alg");
            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));

            /* key_share_send() requires a negotiated_curve */
            conn->secure.client_ecc_params[0].negotiated_curve = &s2n_ecc_supported_curves[0];

            uint8_t size = s2n_extensions_server_key_share_send_size(conn)
                + s2n_extensions_server_supported_versions_size()
                + EXTENSION_LEN;

            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&conn->secure.client_ecc_params[0]));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size);

            /* Test that s2n_server_extensions_send() do not send extension < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
    return 0;
}
