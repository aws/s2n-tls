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

#include <s2n.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_ecc_preferences.h"

#include "utils/s2n_safety.h"

const uint8_t SESSION_ID_SIZE = 1;
const uint8_t COMPRESSION_METHOD_SIZE = 1;

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
const char hello_retry_random_hex[] =
    "CF21AD74E59A6111BE1D8C021E65B891"
    "C2A211167ABB8C5E079E09E2C8A8339C";


const uint8_t tls12_downgrade_protection_check_bytes[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

const uint8_t tls11_downgrade_protection_check_bytes[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test basic Server Hello Send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

        /* Test s2n_server_hello_send */
        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_server_hello_send(conn));
        EXPECT_EQUAL(hello_stuffer->blob.data[0], 0x03);
        EXPECT_EQUAL(hello_stuffer->blob.data[1], 0x03);
        S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, total);

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that legacy_version_field is set correct for TLS 1.3 Server Hello Send */
    {
        EXPECT_SUCCESS(s2n_enable_tls13());
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_NOT_NULL(conn->config);
        const struct s2n_ecc_preferences *ecc_preferences = config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_preferences);
        /* configure these parameters so server hello can be sent */
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
        conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_preferences->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_send(conn));

        /* verify that legacy protocol version is 0x0303 (TLS12) */
        EXPECT_EQUAL(hello_stuffer->blob.data[0], 0x03);
        EXPECT_EQUAL(hello_stuffer->blob.data[1], 0x03);

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));

        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    /* Test basic Server Hello Recv */
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

        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Test s2n_server_hello_recv() */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test TLS 1.3 session id matching */
    {
        EXPECT_SUCCESS(s2n_enable_tls13());
        struct s2n_config *client_config;
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_stuffer *io = &client_conn->handshake.io;
        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        /* random payload */
        uint8_t random[S2N_TLS_RANDOM_DATA_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, random, S2N_TLS_RANDOM_DATA_LEN));

        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = {0};

        /* generate matching session id for payload and client connection */
        for (int i = 0; i < 32; i++) {
            session_id[i] = i;
            client_conn->session_id[i] = i;
        }

        /* session id */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, (0x13 << 8) + 0x01)); /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0)); /* no compression */

        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->session_id_len = 32;

        /* Test s2n_server_hello_recv() */
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(io), 0);

        /* Check that corrupt session id fails server hello */
        for (int i = 0; i < 32; i++) {
            client_conn->session_id[i] ^= 1;
            EXPECT_SUCCESS(s2n_stuffer_reread(io));
            EXPECT_FAILURE(s2n_server_hello_recv(client_conn));
            client_conn->session_id[i] ^= 1;
        }

        /* Check that server hello is successful again */
        EXPECT_SUCCESS(s2n_stuffer_reread(io));
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        /* Check that unmatched session length should also fail */
        for (int i = 0; i < 32; i++) {
            client_conn->session_id_len = i;
            EXPECT_SUCCESS(s2n_stuffer_reread(io));
            EXPECT_FAILURE(s2n_server_hello_recv(client_conn));
        }

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    /* Test TLS 1.3 => 1.1 protocol downgrade detection with a TLS1.3 client */
    {
        EXPECT_SUCCESS(s2n_enable_tls13());
        struct s2n_config *client_config;
        struct s2n_connection *client_conn;
        struct s2n_config *server_config;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* The client will request TLS1.3 */
        client_conn->client_protocol_version = S2N_TLS13;

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        /* The server will respond with TLS1.1 even though it supports TLS1.3 */
        server_conn->actual_protocol_version = S2N_TLS11;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that the downgrade is detected */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_BYTEARRAY_EQUAL(&client_stuffer->blob.data[S2N_TLS_PROTOCOL_VERSION_LEN + 24], tls11_downgrade_protection_check_bytes, 8);
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED);

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    /* Test TLS 1.3 => 1.2 protocol downgrade detection with a TLS1.3 client */
    {
        EXPECT_SUCCESS(s2n_enable_tls13());
        struct s2n_config *client_config;
        struct s2n_connection *client_conn;
        struct s2n_config *server_config;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* The client will request TLS1.3 */
        client_conn->client_protocol_version = S2N_TLS13;

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        /* The server will respond with TLS1.2 even though it supports TLS1.3 */
        server_conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that the downgrade is detected */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_BYTEARRAY_EQUAL(&client_stuffer->blob.data[S2N_TLS_PROTOCOL_VERSION_LEN + 24], tls12_downgrade_protection_check_bytes, 8);
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED);

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    /* Verify a TLS1.2 client can negotiate with a TLS1.3 server */
    {
        struct s2n_config *client_config;
        struct s2n_connection *client_conn;
        struct s2n_config *server_config;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* The client will request TLS1.2 */
        client_conn->client_protocol_version = S2N_TLS12;

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        /* The server will respond with TLS1.2 even though it support TLS1.3. This is expected because */
        /* the client only support TLS1.2 */
        EXPECT_SUCCESS(s2n_enable_tls13());
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that a TLS12 client does not error due to the downgrade */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Verify a TLS1.3 client can negotiate with a TLS1.2 server */
    {
        struct s2n_config *client_config;
        struct s2n_connection *client_conn;
        struct s2n_config *server_config;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* The client will request TLS1.3 */
        client_conn->client_protocol_version = S2N_TLS13;

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        /* The server will respond with TLS1.2 */
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that a TLS13 client does not error due to the downgrade */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        GUARD(s2n_enable_tls13());
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        GUARD(s2n_disable_tls13());
        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Verify a TLS1.2 client can negotiate with a TLS1.3 server */
    {
        struct s2n_config *client_config;
        struct s2n_connection *client_conn;
        struct s2n_config *server_config;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* The client will request TLS1.2 */
        client_conn->client_protocol_version = S2N_TLS12;

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        /* The server will respond with TLS1.2 even though it support TLS1.3. This is expected because */
        /* the client only support TLS1.2 */
        EXPECT_SUCCESS(s2n_enable_tls13());
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that a TLS12 client does not error due to the downgrade */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* TLS13 hello retry message received results into S2N_ERR_UNIMPLEMENTED error*/
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_stuffer *io = &client_conn->handshake.io;
        client_conn->server_protocol_version = S2N_TLS13;

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = {0};
        S2N_BLOB_FROM_HEX(random_blob, hello_retry_random_hex);
        /* random payload */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, random_blob.data, S2N_TLS_RANDOM_DATA_LEN));
        /* session id */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));
        /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, (0x13 << 8) + 0x01));
        /* no compression */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));
        EXPECT_EQUAL(S2N_TLS_RANDOM_DATA_LEN, random_blob.size);
        /* Test s2n_server_hello_recv() fails with Unimplemented method error */
        EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_server_hello_recv(client_conn), S2N_ERR_UNIMPLEMENTED);
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    END_TEST();

    return 0;
}
