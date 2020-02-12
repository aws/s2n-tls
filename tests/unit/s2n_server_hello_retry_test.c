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

#include "tls/extensions/s2n_key_share.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#include "tls/extensions/s2n_server_key_share.h"

#include "error/s2n_errno.h"

const uint8_t SESSION_ID_SIZE = 1;
const uint8_t COMPRESSION_METHOD_SIZE = 1;

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
const uint8_t retry_random[S2N_TLS_RANDOM_DATA_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Send and receive Hello Retry Request messages */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

        uint16_t expected_length = 6;
        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, expected_length);
        
        server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        server_conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[0]));

        /* The client will need a key share extension to properly parse the hello */
        /* ??? + Total extension size */
        server_conn->handshake.requires_retry = 1;
        total += 2 + 2 + S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE + s2n_extensions_server_key_share_send_size(server_conn);
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
        total += 2 + 2 + 2 + 32;

        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Test s2n_server_hello_recv() */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        client_conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->secure.client_ecc_evp_params[0]));

        memcpy_check(client_conn->secure.server_random, retry_random, S2N_TLS_RANDOM_DATA_LEN);
        client_conn->server_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_EQUAL(client_conn->handshake.client_received_hrr, 1);
        EXPECT_EQUAL(server_conn->handshake.server_sent_hrr, 1);

        /* Verify that multiple hello retry messages will fail */
        EXPECT_SUCCESS(s2n_stuffer_reread(client_stuffer));
        EXPECT_FAILURE(s2n_server_hello_recv(client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Verify an empty key share extension causes a Hello Retry Request to be sent */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        conn->client_protocol_version = S2N_TLS13;
        conn->server_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_server_hello_send(conn));

        /* EXPECT_EQUAL(conn->handshake.server_sent_hrr, 1); */

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Retry requests with incorrect random data are not accepted */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        struct s2n_stuffer *io = &conn->handshake.io;
        conn->server_protocol_version = S2N_TLS13;

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        /* random data */
        uint8_t bad_retry_random[S2N_TLS_RANDOM_DATA_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, bad_retry_random, S2N_TLS_RANDOM_DATA_LEN));

        /* session id */
        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));

        /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, (0x13 << 8) + 0x01));

        /* no compression */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(conn->handshake.client_received_hrr, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Retry requests without a supported version extension are not accepted */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        struct s2n_stuffer *io = &conn->handshake.io;
        conn->server_protocol_version = S2N_TLS13;

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        /* random data */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, retry_random, S2N_TLS_RANDOM_DATA_LEN));

        /* session id */
        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));

        /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, (0x13 << 8) + 0x01));

        /* no compression */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(conn->handshake.client_received_hrr, 0);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());

    END_TEST();
}
