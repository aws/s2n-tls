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

#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_client_renegotiation_info.h"

int s2n_parse_client_hello(struct s2n_connection *conn);

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const uint8_t renegotiation_info_scsv_iana[] = { TLS_EMPTY_RENEGOTIATION_INFO_SCSV };

    /* Test receive - too much data */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_renegotiation_info_extension.recv(conn, &stuffer),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_FALSE(conn->secure_renegotiation);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test receive - value not 0
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *= type=test
     *# The server MUST then verify
     *# that the length of the "renegotiated_connection" field is zero,
     *# and if it is not, MUST abort the handshake.
     */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 1));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_renegotiation_info_extension.recv(conn, &stuffer),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_FALSE(conn->secure_renegotiation);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test receive */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_renegotiation_info_extension.recv(conn, &stuffer));
        EXPECT_TRUE(conn->secure_renegotiation);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test receive when using SSLv3
     *
     *= https://tools.ietf.org/rfc/rfc5746#4.5
     *= type=test
     *# TLS servers that support secure renegotiation and support SSLv3 MUST accept SCSV or the
     *# "renegotiation_info" extension and respond as described in this
     *# specification even if the offered client version is {0x03, 0x00}.
     **/
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        server_conn->server_protocol_version = S2N_SSLv3;
        server_conn->actual_protocol_version = S2N_SSLv3;
        EXPECT_SUCCESS(s2n_client_renegotiation_info_extension.recv(server_conn, &extension));
        EXPECT_TRUE(server_conn->secure_renegotiation);
    }

    /*
     *= https://tools.ietf.org/rfc/rfc5746#3.4
     *= type=test
     *# o  The client MUST include either an empty "renegotiation_info"
     *#    extension, or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling
     *#    cipher suite value in the ClientHello.  Including both is NOT
     *#    RECOMMENDED.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        /* Process the client hello on the server */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_parse_client_hello(server_conn));

        /* Expect TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
        bool found_renegotiation_info_scsv = false;
        for (size_t i = 0; i < server_conn->client_hello.cipher_suites.size; i += S2N_TLS_CIPHER_SUITE_LEN) {
            uint8_t *iana = server_conn->client_hello.cipher_suites.data + i;
            if (memcmp(iana, renegotiation_info_scsv_iana, S2N_TLS_CIPHER_SUITE_LEN) == 0) {
                found_renegotiation_info_scsv = true;
            }
        }
        EXPECT_TRUE(found_renegotiation_info_scsv);

        /* Do NOT expect "renegotiation_info" extension */
        s2n_extension_type_id extension_id = 0;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(
                s2n_client_renegotiation_info_extension.iana_value, &extension_id));
        s2n_parsed_extension *extension = &server_conn->client_hello.extensions.parsed_extensions[extension_id];
        EXPECT_EQUAL(extension->extension.size, 0);
        EXPECT_EQUAL(extension->extension_type, 0);
    }

    /**
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *= type=test
     *# o  The server MUST check if the "renegotiation_info" extension is
     *# included in the ClientHello.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        /* s2n-tls clients do not send the "renegotiation_info" extension.
         * Instead, they send the TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite.
         * See previous test.
         */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        /* Process the extensions on the server */
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_parse_client_hello(server_conn));
        EXPECT_SUCCESS(s2n_extension_list_process(S2N_EXTENSION_LIST_CLIENT_HELLO, server_conn,
                &server_conn->client_hello.extensions));

        /* Expect secure renegotiation to still be false: no extension received */
        EXPECT_FALSE(server_conn->secure_renegotiation);

        /* Manually append the "renegotiation_info" extension to the original list. */
        uint8_t extension[] = {
                0xff, 0x01, /* extension type: renegotiation_info */
                0x00, 0x01, /* extension length: 1 */
                0x00, /* renegotiated_connection length: 0 */
        };
        size_t client_hello_size = server_conn->client_hello.raw_message.size;
        size_t old_extensions_size = server_conn->client_hello.extensions.raw.size;
        size_t new_extensions_size = old_extensions_size + sizeof(extension);
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&client_conn->handshake.io,
                client_hello_size - old_extensions_size - sizeof(uint16_t)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, new_extensions_size));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&client_conn->handshake.io, old_extensions_size));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&client_conn->handshake.io, extension, sizeof(extension)));

        /* Process the extensions on the server again */
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_parse_client_hello(server_conn));
        EXPECT_SUCCESS(s2n_extension_list_process(S2N_EXTENSION_LIST_CLIENT_HELLO, server_conn,
                &server_conn->client_hello.extensions));

        /* Expect secure renegotiation to be true: extension received */
        EXPECT_TRUE(server_conn->secure_renegotiation);
    }

    /* Test: should_send during renegotiation handshake
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.5
     *= type=test
     *# o  The client MUST include the "renegotiation_info" extension in the
     *#    ClientHello
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* Not included by default */
        EXPECT_FALSE(s2n_client_renegotiation_info_extension.should_send(conn));

        /* Included if renegotiation enabled */
        conn->handshake.renegotiation = true;
        EXPECT_TRUE(s2n_client_renegotiation_info_extension.should_send(conn));
    }

    /* Test: send during renegotiation handshake
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.5
     *= type=test
     *# o  The client MUST include the "renegotiation_info" extension in the
     *#    ClientHello, containing the saved client_verify_data.
     */
    {
        /* Send client_verify_data */
        {
            const uint8_t client_verify_data[] = "client verify data";

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->handshake.renegotiation = true;

            /* Setup client_verify_data */
            EXPECT_MEMCPY_SUCCESS(conn->handshake.client_finished,
                    client_verify_data, sizeof(client_verify_data));
            conn->handshake.finished_len = sizeof(client_verify_data);

            /* Error if secure renegotiation not supported */
            {
                conn->secure_renegotiation = false;

                DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
                EXPECT_FAILURE_WITH_ERRNO(s2n_client_renegotiation_info_extension.send(conn, &out),
                        S2N_ERR_NO_RENEGOTIATION);
            }

            /* Success if secure renegotiation supported */
            {
                conn->secure_renegotiation = true;

                DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
                EXPECT_SUCCESS(s2n_client_renegotiation_info_extension.send(conn, &out));

                uint8_t actual_len = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &actual_len));
                EXPECT_EQUAL(actual_len, sizeof(client_verify_data));

                uint8_t *actual_data = s2n_stuffer_raw_read(&out, actual_len);
                EXPECT_BYTEARRAY_EQUAL(actual_data, client_verify_data, actual_len);
            }
        }

        /*
         *= https://tools.ietf.org/rfc/rfc5746#3.5
         *= type=test
         *# The SCSV MUST NOT be included.
         */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->secure_renegotiation = true;
            conn->handshake.renegotiation = true;

            EXPECT_SUCCESS(s2n_client_hello_send(conn));
            EXPECT_SUCCESS(s2n_parse_client_hello(conn));

            /* Expect TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
            bool found_renegotiation_info_scsv = false;
            for (size_t i = 0; i < conn->client_hello.cipher_suites.size; i += S2N_TLS_CIPHER_SUITE_LEN) {
                uint8_t *iana = conn->client_hello.cipher_suites.data + i;
                if (memcmp(iana, renegotiation_info_scsv_iana, S2N_TLS_CIPHER_SUITE_LEN) == 0) {
                    found_renegotiation_info_scsv = true;
                }
            }
            EXPECT_FALSE(found_renegotiation_info_scsv);
        }
    }

    END_TEST();
}
