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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
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

static S2N_RESULT s2n_test_client_hello(struct s2n_connection *client_conn, struct s2n_connection *server_conn)
{
    /* We have to "write" the handshake header for the PSK binder calculation, which expects a complete
     * ClientHello message. We'll skip these bytes later.
     */
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&client_conn->handshake.io, TLS_HANDSHAKE_HEADER_LENGTH));

    RESULT_GUARD_POSIX(s2n_client_hello_send(client_conn));
    RESULT_GUARD_POSIX(s2n_stuffer_copy(&client_conn->handshake.io,
            &server_conn->handshake.io, s2n_stuffer_data_available(&client_conn->handshake.io)));

    /* Skip the handshake header bytes */
    RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&server_conn->handshake.io, TLS_HANDSHAKE_HEADER_LENGTH));

    RESULT_GUARD_POSIX(s2n_client_hello_recv(server_conn));

    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&client_conn->handshake.io));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&server_conn->handshake.io));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

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
    };

    /* Test that legacy_version_field is set correct for TLS 1.3 Server Hello Send */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        struct s2n_config *config = NULL;
        const struct s2n_ecc_preferences *ecc_preferences = NULL;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_NOT_NULL(conn->config);
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_NOT_NULL(ecc_preferences);
        /* configure these parameters so server hello can be sent */
        conn->actual_protocol_version = S2N_TLS13;
        conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
        conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_send(conn));

        /* verify that legacy protocol version is 0x0303 (TLS12) */
        EXPECT_EQUAL(hello_stuffer->blob.data[0], 0x03);
        EXPECT_EQUAL(hello_stuffer->blob.data[1], 0x03);

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));

        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

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

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Test s2n_server_hello_recv() */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test Server Hello Recv with invalid cipher */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        server_conn->actual_protocol_version = S2N_TLS12;

        /* This cipher is not in the client's default selection */
        server_conn->secure->cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* The client should fail the handshake because an invalid cipher was offered */
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_CIPHER_NOT_SUPPORTED);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Non-matching session IDs turn off EMS for the connection */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;

        /* Create session ID for server */
        for (int i = 0; i < 32; i++) {
            server_conn->session_id[i] = i;
        }

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Create client session ID does not match server session ID */
        for (int i = 0; i < 32; i++) {
            client_conn->session_id[i] = 0;
        }

        /* Client is negotiating an EMS connection but is able to fallback to non-EMS connection
         * if session IDs don't match */
        client_conn->ems_negotiated = true;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        EXPECT_FALSE(client_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test TLS 1.3 session id matching */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
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
        uint8_t random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, random, S2N_TLS_RANDOM_DATA_LEN));

        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = { 0 };

        /* generate matching session id for payload and client connection */
        for (int i = 0; i < 32; i++) {
            session_id[i] = i;
            client_conn->session_id[i] = i;
        }

        /* session id */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, (0x13 << 8) + 0x01)); /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));                   /* no compression */

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
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* Test TLS 1.3 => 1.1 protocol downgrade detection with a TLS1.3 client */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
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

        /* Set the negotiated curve, otherwise the server might try to respond with a retry */
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        /* The server will respond with TLS1.1 even though it supports TLS1.3 */
        server_conn->actual_protocol_version = S2N_TLS11;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
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
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* Test TLS 1.3 => 1.2 protocol downgrade detection with a TLS1.3 client */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
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

        /* Set the negotiated curve, otherwise the server might try to respond with a retry */
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        /* The server will respond with TLS1.2 even though it supports TLS1.3 */
        server_conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
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
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

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

        /* The server will respond with TLS1.2 even though it support TLS1.3. This is expected because */
        /* the client only support TLS1.2 */
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that a TLS12 client does not error due to the downgrade */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

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

        /* The server will respond with TLS1.2 */
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->actual_protocol_version = S2N_TLS12;

        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that a TLS13 client does not error due to the downgrade */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        POSIX_GUARD(s2n_enable_tls13_in_test());
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        POSIX_GUARD(s2n_disable_tls13_in_test());
        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

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

        /* The server will respond with TLS1.2 even though it support TLS1.3. This is expected because */
        /* the client only support TLS1.2 */
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        server_conn->actual_protocol_version = S2N_TLS12;

        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());

        /* Copy server stuffer to client stuffer */
        const uint32_t total = s2n_stuffer_data_available(&server_conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Verify that a TLS12 client does not error due to the downgrade */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* TLS13 hello retry message received results into S2N_ERR_UNIMPLEMENTED error*/
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_stuffer *io = &client_conn->handshake.io;
        client_conn->server_protocol_version = S2N_TLS13;

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = { 0 };
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

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* Test that negotiating TLS1.2 with QUIC-enabled client fails */
    if (s2n_is_tls13_fully_supported()) {
        EXPECT_SUCCESS(s2n_reset_tls13_in_test());

        struct s2n_config *quic_config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(quic_config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(quic_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_enable_quic(quic_config));

        struct s2n_config *non_quic_config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(non_quic_config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(non_quic_config, chain_and_key));

        /* Succeeds when negotiating TLS1.3 */
        if (s2n_is_tls13_fully_supported()) {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, non_quic_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, non_quic_config));

            EXPECT_OK(s2n_test_client_hello(client_conn, server_conn));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, quic_config));

            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io,
                    &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Fails when negotiating TLS1.2 */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, non_quic_config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all_tls12"));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, non_quic_config));

            EXPECT_OK(s2n_test_client_hello(client_conn, server_conn));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, quic_config));

            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io,
                    &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        EXPECT_SUCCESS(s2n_config_free(quic_config));
        EXPECT_SUCCESS(s2n_config_free(non_quic_config));
    }

    /* Test that negotiating TLS1.2 with an early data enabled client fails.
     *
     *= https://tools.ietf.org/rfc/rfc8446#appendix-D.3
     *= type=test
     *# A client that attempts to send 0-RTT data MUST fail a connection if
     *# it receives a ServerHello with TLS 1.2 or older.
     */
    if (s2n_is_tls13_fully_supported()) {
        EXPECT_SUCCESS(s2n_reset_tls13_in_test());

        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Succeeds when negotiating TLS1.3 */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_128_gcm_sha256));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 1, &s2n_tls13_aes_128_gcm_sha256));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_test_client_hello(client_conn, server_conn));

            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io,
                    &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(client_conn->server_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* TLS 1.3 Client Early Data is rejected when server only supports TLS1.2 */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_128_gcm_sha256));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all_tls12"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 1, &s2n_tls13_aes_128_gcm_sha256));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_test_client_hello(client_conn, server_conn));

            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io,
                    &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(client_conn->server_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    END_TEST();
}
