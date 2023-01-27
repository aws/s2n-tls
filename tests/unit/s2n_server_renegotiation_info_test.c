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

#include "tls/extensions/s2n_server_renegotiation_info.h"

#include <stdint.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_server_renegotiation_info_extension_write(struct s2n_stuffer *out,
        const uint8_t *client_verify_data, const uint8_t *server_verify_data, uint8_t verify_data_len)
{
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(out, verify_data_len * 3));

    struct s2n_stuffer_reservation len = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_uint8(out, &len));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(out, client_verify_data, verify_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(out, server_verify_data, verify_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_write_vector_size(&len));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    const uint8_t client_verify_data[] = "client verify data";
    const uint8_t server_verify_data[] = "server verify data";
    EXPECT_EQUAL(sizeof(client_verify_data), sizeof(server_verify_data));
    const uint8_t verify_data_len = sizeof(server_verify_data);

    /* Test should_send
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *= type=test
     *# o  If the secure_renegotiation flag is set to TRUE, the server MUST
     *#    include an empty "renegotiation_info" extension in the ServerHello
     *#    message.
     */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* TLS1.2 and secure renegotiation not enabled -> DON'T send */
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure_renegotiation = false;
        EXPECT_FALSE(s2n_server_renegotiation_info_extension.should_send(conn));

        /* TLS1.3 and secure renegotiation not enabled -> DON'T send */
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure_renegotiation = false;
        EXPECT_FALSE(s2n_server_renegotiation_info_extension.should_send(conn));

        /* TLS1.3 and secure renegotiation enabled -> DON'T send */
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure_renegotiation = true;
        EXPECT_FALSE(s2n_server_renegotiation_info_extension.should_send(conn));

        /* TLS1.2 and secure renegotiation enabled -> send */
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure_renegotiation = true;
        EXPECT_TRUE(s2n_server_renegotiation_info_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test server_renegotiation_info send and recv during initial handshake
     *
     *= https://tools.ietf.org/rfc/rfc5746#4.3
     *= type=test
     *# In order to enable clients to probe, even servers that do not support
     *# renegotiation MUST implement the minimal version of the extension
     *# described in this document for initial handshakes, thus signaling
     *# that they have been upgraded.
     */
    {
        struct s2n_connection *server_conn, *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer extension = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure_renegotiation = 1;

        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(server_conn, &extension));
        EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&extension), 0);

        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.recv(client_conn, &extension));
        EXPECT_EQUAL(client_conn->secure_renegotiation, 1);
        EXPECT_EQUAL(s2n_stuffer_data_available(&extension), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test server_renegotiation_info recv when using SSLv3
     *
     *= https://tools.ietf.org/rfc/rfc5746#4.5
     *= type=test
     *# Clients that support SSLv3 and offer secure renegotiation (either via SCSV or
     *# "renegotiation_info") MUST accept the "renegotiation_info" extension
     *# from the server, even if the server version is {0x03, 0x00}, and
     *# behave as described in this specification.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure_renegotiation = true;
        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(server_conn, &extension));
        EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&extension), 0);

        client_conn->client_protocol_version = S2N_SSLv3;
        client_conn->actual_protocol_version = S2N_SSLv3;
        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.recv(client_conn, &extension));
        EXPECT_EQUAL(client_conn->secure_renegotiation, 1);
        EXPECT_EQUAL(s2n_stuffer_data_available(&extension), 0);
    };

    /* Test server_renegotiation_info recv during initial handshake - extension too long */
    {
        struct s2n_connection *server_conn, *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer extension = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure_renegotiation = 1;

        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(server_conn, &extension));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(client_conn, &extension),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_EQUAL(client_conn->secure_renegotiation, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test server_renegotiation_info recv during initial handshake - extension length wrong
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.4
     *= type=test
     *# *  The client MUST then verify that the length of the
     *#    "renegotiated_connection" field is zero, and if it is not, MUST
     *#    abort the handshake (by sending a fatal handshake_failure alert).
     */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer extension = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 5));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(client_conn, &extension),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_EQUAL(client_conn->secure_renegotiation, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* Test: if_missing during initial handshake is a no-op
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.4
     *= type=test
     *# *  If the extension is not present, the server does not support
     *#    secure renegotiation; set secure_renegotiation flag to FALSE.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.if_missing(conn));
        EXPECT_FALSE(conn->secure_renegotiation);
    };

    /* Test: if_missing during renegotiation handshake is an error
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.5
     *= type=test
     *# o  When a ServerHello is received, the client MUST verify that the
     *#    "renegotiation_info" extension is present; if it is not, the
     *#    client MUST abort the handshake.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->handshake.renegotiation = true;
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.if_missing(conn),
                S2N_ERR_NO_RENEGOTIATION);
    };

    /* Test: recv during renegotiation handshake
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.5
     *= type=test
     *# o  The client MUST then verify that the first half of the
     *#    "renegotiated_connection" field is equal to the saved
     *#    client_verify_data value, and the second half is equal to the
     *#    saved server_verify_data value.  If they are not, the client MUST
     *#    abort the handshake.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->handshake.renegotiation = true;
        conn->secure_renegotiation = true;

        /* Setup verify_data */
        EXPECT_MEMCPY_SUCCESS(conn->handshake.client_finished,
                client_verify_data, sizeof(client_verify_data));
        EXPECT_MEMCPY_SUCCESS(conn->handshake.server_finished,
                server_verify_data, sizeof(server_verify_data));
        conn->handshake.finished_len = verify_data_len;
        uint8_t renegotiation_info_len = verify_data_len * 2;

        /* Secure renegotiation not supported */
        {
            /* Write valid verify_data */
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_server_renegotiation_info_extension_write(&extension,
                    client_verify_data, server_verify_data, verify_data_len));

            conn->secure_renegotiation = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(conn, &extension),
                    S2N_ERR_NO_RENEGOTIATION);
        };

        /* Turn on secure renegotiation for the rest of the tests */
        conn->secure_renegotiation = true;

        /* Receive valid client and server verify_data */
        {
            /* Write valid verify_data */
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_server_renegotiation_info_extension_write(&extension,
                    client_verify_data, server_verify_data, verify_data_len));

            EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.recv(conn, &extension));
        };

        /* Receive incorrect length: too small */
        {
            /* Write valid verify_data */
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_server_renegotiation_info_extension_write(&extension,
                    client_verify_data, server_verify_data, verify_data_len));

            /* Modify length */
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&extension));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, renegotiation_info_len - 1));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&extension, renegotiation_info_len));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(conn, &extension),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Receive incorrect length: too large */
        {
            /* Write valid verify_data */
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_server_renegotiation_info_extension_write(&extension,
                    client_verify_data, server_verify_data, verify_data_len));

            /* Modify length */
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&extension));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, renegotiation_info_len + 1));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&extension, renegotiation_info_len));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(conn, &extension),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Receive incorrect client_verify_data */
        {
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_server_renegotiation_info_extension_write(&extension,
                    server_verify_data, server_verify_data, verify_data_len));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(conn, &extension),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Receive incorrect server_verify_data */
        {
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_server_renegotiation_info_extension_write(&extension,
                    client_verify_data, client_verify_data, verify_data_len));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(conn, &extension),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Receive initial handshake extension */
        {
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            conn->handshake.renegotiation = false;
            EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(conn, &extension));
            conn->handshake.renegotiation = true;
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(conn, &extension),
                    S2N_ERR_BAD_MESSAGE);
        };
    };

    /* Test send during renegotiation handshake
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.7
     *= type=test
     *# o  The server MUST include a "renegotiation_info" extension
     *#    containing the saved client_verify_data and server_verify_data in
     *#    the ServerHello.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        client_conn->handshake.renegotiation = true;
        client_conn->secure_renegotiation = true;
        EXPECT_MEMCPY_SUCCESS(client_conn->handshake.client_finished,
                client_verify_data, sizeof(client_verify_data));
        EXPECT_MEMCPY_SUCCESS(client_conn->handshake.server_finished,
                server_verify_data, sizeof(server_verify_data));
        client_conn->handshake.finished_len = verify_data_len;

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        server_conn->handshake.renegotiation = true;
        server_conn->secure_renegotiation = true;
        EXPECT_MEMCPY_SUCCESS(server_conn->handshake.client_finished,
                client_verify_data, sizeof(client_verify_data));
        EXPECT_MEMCPY_SUCCESS(server_conn->handshake.server_finished,
                server_verify_data, sizeof(server_verify_data));
        server_conn->handshake.finished_len = verify_data_len;

        DEFER_CLEANUP(struct s2n_stuffer sent_extension = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&sent_extension, 0));
        EXPECT_TRUE(s2n_server_renegotiation_info_extension.should_send(client_conn));
        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(client_conn, &sent_extension));

        /* Verify matches test method */
        DEFER_CLEANUP(struct s2n_stuffer test_extension = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_server_renegotiation_info_extension_write(&test_extension,
                client_verify_data, server_verify_data, verify_data_len));
        EXPECT_EQUAL(s2n_stuffer_data_available(&sent_extension), s2n_stuffer_data_available(&test_extension));
        EXPECT_BYTEARRAY_EQUAL(sent_extension.blob.data, test_extension.blob.data,
                s2n_stuffer_data_available(&sent_extension));

        /* Verify we can recv what we send */
        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.recv(server_conn, &sent_extension));
    };

    /* Functional Test
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.4
     *= type=test
     *# o  When a ServerHello is received, the client MUST check if it
     *#    includes the "renegotiation_info" extension:
     */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Send and receive the ClientHello */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Test "renegotiation_info" extension NOT included during initial handshake */
        {
            EXPECT_FALSE(client_conn->secure_renegotiation);

            server_conn->secure_renegotiation = false;
            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

            EXPECT_FALSE(client_conn->secure_renegotiation);
        };

        /* Test "renegotiation_info" extension included during initial handshake */
        {
            EXPECT_FALSE(client_conn->secure_renegotiation);

            server_conn->secure_renegotiation = true;
            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

            EXPECT_TRUE(client_conn->secure_renegotiation);
        };
    };

    /* Functional Test: SSLv3
     *
     *= https://tools.ietf.org/rfc/rfc5746#4.5
     *= type=test
     *# Clients that support SSLv3 and offer secure renegotiation (either via SCSV or
     *# "renegotiation_info") MUST accept the "renegotiation_info" extension
     *# from the server, even if the server version is {0x03, 0x00}, and
     *# behave as described in this specification.  TLS servers that support
     *# secure renegotiation and support SSLv3 MUST accept SCSV or the
     *# "renegotiation_info" extension and respond as described in this
     *# specification even if the offered client version is {0x03, 0x00}.
     **/
    if (s2n_hash_is_available(S2N_HASH_MD5)) {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all"));
        client_conn->client_protocol_version = S2N_SSLv3;
        client_conn->actual_protocol_version = S2N_SSLv3;

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all"));
        server_conn->server_protocol_version = S2N_SSLv3;
        server_conn->actual_protocol_version = S2N_SSLv3;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(client_conn->secure_renegotiation);
        EXPECT_TRUE(server_conn->secure_renegotiation);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_SSLv3);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_SSLv3);
    }

    END_TEST();
    return 0;
}
