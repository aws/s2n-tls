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

#include "tls/s2n_client_hello.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_sslv2_client_hello.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_client_hello.c"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"

#define ZERO_TO_THIRTY_ONE 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

#define LENGTH_TO_SESSION_ID        (S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN)
#define TLS12_LENGTH_TO_CIPHER_LIST (LENGTH_TO_SESSION_ID + 1)
#define TLS13_LENGTH_TO_CIPHER_LIST (TLS12_LENGTH_TO_CIPHER_LIST + S2N_TLS_SESSION_ID_MAX_LEN)

int s2n_parse_client_hello(struct s2n_connection *conn);

int main(int argc, char **argv)
{
    struct s2n_cert_chain_and_key *chain_and_key, *ecdsa_chain_and_key;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Test s2n_client_hello_get_extension_by_id */
    {
        /* Test with invalid parsed extensions */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            s2n_tls_extension_type test_extension_type = S2N_EXTENSION_SERVER_NAME;

            s2n_extension_type_id test_extension_type_id;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(test_extension_type, &test_extension_type_id));

            uint8_t data[] = "data";
            s2n_parsed_extension *parsed_extension = &conn->client_hello.extensions.parsed_extensions[test_extension_type_id];
            parsed_extension->extension_type = test_extension_type;
            parsed_extension->extension.data = data;
            parsed_extension->extension.size = sizeof(data);

            /* Succeeds with correct extension type */
            EXPECT_EQUAL(s2n_client_hello_get_extension_by_id(&conn->client_hello,
                                 test_extension_type, data, sizeof(data)),
                    sizeof(data));

            /* Fails with wrong extension type */
            parsed_extension->extension_type = test_extension_type + 1;
            EXPECT_EQUAL(s2n_client_hello_get_extension_by_id(&conn->client_hello,
                                 test_extension_type, data, sizeof(data)),
                    0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_client_hello_has_extension */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        uint8_t data[] = {
            /* arbitrary extension with 2 data */
            0xFF, 0x00, /* extension type */
            0x00, 0x02, /* extension payload length */
            0xAB, 0xCD, /* extension payload */
            /* Encrypt then mac extension without data */
            0x00, 0x16,
            0x00, 0x00
        };

        struct s2n_blob *raw_extension = &conn->client_hello.extensions.raw;
        raw_extension->data = data;
        raw_extension->size = sizeof(data);

        /* Succeeds on an unsupported extension with no payload */
        bool exists = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&conn->client_hello, 0x0016, &exists));
        EXPECT_TRUE(exists);

        /* Succeeds on an unsupported extension with payload */
        exists = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&conn->client_hello, 0xFF00, &exists));
        EXPECT_TRUE(exists);

        /* Succeeds with an invalid extension */
        exists = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&conn->client_hello, 0xFFFF, &exists));
        EXPECT_FALSE(exists);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_client_hello_has_extension with a zero-length extension */
    for (int send_sct = 0; send_sct <= 1; send_sct++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* The SCT extension is zero-length. */
        if (send_sct) {
            EXPECT_SUCCESS(s2n_config_set_ct_support_level(config, S2N_CT_SUPPORT_REQUEST));
        }

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_client_hello_send(client));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                s2n_stuffer_data_available(&client->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server));

        struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
        EXPECT_NOT_NULL(client_hello);

        s2n_parsed_extension *sct_extension = NULL;
        int ret = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, &client_hello->extensions,
                &sct_extension);

        if (send_sct) {
            /* Ensure that the extension was received. */
            EXPECT_SUCCESS(ret);
            POSIX_ENSURE_REF(sct_extension);

            /* Ensure that the extension is zero-length. */
            EXPECT_EQUAL(sct_extension->extension.size, 0);
        } else {
            /* The extension shouldn't have been received because it wasn't requested. */
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_EXTENSION_NOT_RECEIVED);
        }
    }

    /* Test s2n_client_hello_get_raw_extension */
    {
        uint8_t data[] = {
            /* arbitrary extension with 2 data */
            0xFF, 0x00, /* extension type */
            0x00, 0x02, /* extension payload length */
            0xAB, 0xCD, /* extension payload */
            /* NPN extension without data */
            0x33, 0x74,
            0x00, 0x00
        };
        struct s2n_blob raw_extension = {
            .data = data,
            .size = sizeof(data),
        };

        struct s2n_blob extension = { 0 };
        /* Succeeds with extension exists without payload */
        EXPECT_OK(s2n_client_hello_get_raw_extension(0x3374, &raw_extension, &extension));
        EXPECT_EQUAL(extension.size, 0);
        EXPECT_NOT_NULL(extension.data);

        /* Succeeds with extension exists with payload */
        extension = (struct s2n_blob){ 0 };
        EXPECT_OK(s2n_client_hello_get_raw_extension(0xFF00, &raw_extension, &extension));
        EXPECT_EQUAL(extension.size, 2);
        EXPECT_NOT_NULL(extension.data);
        EXPECT_BYTEARRAY_EQUAL(extension.data, &data[4], 2);

        /* Failed with extension not exist */
        extension = (struct s2n_blob){ 0 };
        EXPECT_OK(s2n_client_hello_get_raw_extension(0xFFFF, &raw_extension, &extension));
        EXPECT_EQUAL(extension.size, 0);
        EXPECT_NULL(extension.data);
    };

    /* Test setting cert chain on recv */
    {
        s2n_enable_tls13_in_test();
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        /* TLS13 fails to parse client hello when no certs set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->client_protocol_version = conn->server_protocol_version;
            conn->actual_protocol_version = conn->client_protocol_version;

            EXPECT_SUCCESS(s2n_client_hello_send(conn));
            EXPECT_TRUE(s2n_stuffer_data_available(&conn->handshake.io) > 0);
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_recv(conn), S2N_ERR_INVALID_SIGNATURE_SCHEME);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));

        /* TLS13 successfully sets certs */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->client_protocol_version = conn->server_protocol_version;
            conn->actual_protocol_version = conn->client_protocol_version;

            EXPECT_SUCCESS(s2n_client_hello_send(conn));
            EXPECT_TRUE(s2n_stuffer_data_available(&conn->handshake.io) > 0);
            EXPECT_SUCCESS(s2n_client_hello_recv(conn));

            EXPECT_NOT_NULL(conn->handshake_params.our_chain_and_key);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
        s2n_disable_tls13_in_test();
    };

    /* Test getting supported versions from the client hello */
    if (s2n_is_tls13_fully_supported()) {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));
        /* TLS13 has supported versions in the client hello */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            uint8_t supported_versions[256] = { 0 };
            uint8_t size_of_version_list = 0;
            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io,
                    &server_conn->handshake.io, s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_get_extension_by_id(&server_conn->client_hello,
                    S2N_EXTENSION_SUPPORTED_VERSIONS, supported_versions, sizeof(supported_versions)));
            size_of_version_list = supported_versions[0];
            /* No supported versions before the handshake is received */
            EXPECT_EQUAL(0, size_of_version_list);
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_SUCCESS(s2n_client_hello_get_extension_by_id(&server_conn->client_hello,
                    S2N_EXTENSION_SUPPORTED_VERSIONS, supported_versions, sizeof(supported_versions)));
            size_of_version_list = supported_versions[0];
            EXPECT_TRUE(size_of_version_list > 0);
            bool found_tls13 = false;
            const uint8_t tls13_bytes[] = { 0x03, 0x04 };
            const size_t supported_version_size = sizeof(tls13_bytes);
            for (uint16_t offset = 1; offset < size_of_version_list; offset += supported_version_size) {
                if (memcmp(tls13_bytes, &supported_versions[offset], supported_version_size) == 0) {
                    found_tls13 = true;
                }
            }
            EXPECT_TRUE(found_tls13);
        };
        s2n_disable_tls13_in_test();
    };

    /* Test generating session id */
    {
        const uint8_t test_session_id[S2N_TLS_SESSION_ID_MAX_LEN] = { 7 };

        /* Use session id if already generated */
        for (uint8_t i = S2N_TLS10; i <= S2N_TLS13; i++) {
            if (i >= S2N_TLS13) {
                EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            }

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            conn->session_id_len = S2N_TLS_SESSION_ID_MAX_LEN;
            EXPECT_MEMCPY_SUCCESS(conn->session_id, test_session_id, S2N_TLS_SESSION_ID_MAX_LEN);

            EXPECT_SUCCESS(s2n_client_hello_send(conn));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID));

            uint8_t session_id_length = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &session_id_length));
            EXPECT_EQUAL(session_id_length, S2N_TLS_SESSION_ID_MAX_LEN);

            uint8_t *session_id;
            EXPECT_NOT_NULL(session_id = s2n_stuffer_raw_read(hello_stuffer, S2N_TLS_SESSION_ID_MAX_LEN));
            EXPECT_BYTEARRAY_EQUAL(session_id, test_session_id, S2N_TLS_SESSION_ID_MAX_LEN);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());

        /* With TLS1.3 */
        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());

            /* Generate a session id by default */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID));

                uint8_t session_id_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &session_id_length));
                EXPECT_EQUAL(session_id_length, S2N_TLS_SESSION_ID_MAX_LEN);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* Do NOT generate a session id if middlebox compatibility mode is disabled.
             * For now, middlebox compatibility mode is only disabled by QUIC.
             */
            {
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());
                EXPECT_SUCCESS(s2n_config_enable_quic(config));

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID));

                uint8_t session_id_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &session_id_length));
                EXPECT_EQUAL(session_id_length, 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_config_free(config));
            };

            /* Generate a session id if trying to resume a <TLS1.3 session */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);
                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
                conn->resume_protocol_version = S2N_TLS12;
                EXPECT_TRUE(conn->actual_protocol_version >= S2N_TLS13);
                EXPECT_TRUE(conn->client_protocol_version >= S2N_TLS13);

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID));

                uint8_t session_id_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &session_id_length));
                EXPECT_EQUAL(session_id_length, S2N_TLS_SESSION_ID_MAX_LEN);
            };

            /* Fail if we need to generate a session id to resume a <TLS1.3 session
             * with QUIC support enabled.
             *
             * This should never happen because QUIC requires TLS1.3, so a QUIC
             * client should never receive a valid TLS1.2 ticket from a QUIC server.
             */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);
                conn->resume_protocol_version = S2N_TLS12;
                EXPECT_TRUE(conn->actual_protocol_version >= S2N_TLS13);
                EXPECT_TRUE(conn->client_protocol_version >= S2N_TLS13);
                conn->quic_enabled = true;

                EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_send(conn),
                        S2N_ERR_UNSUPPORTED_WITH_QUIC);
            };

            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        }

        /* With TLS1.2 */
        {
            /* Do NOT generate a session id by default */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID));

                uint8_t session_id_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &session_id_length));
                EXPECT_EQUAL(session_id_length, 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* Generate a session id if using tickets */
            {
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());
                EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID));

                uint8_t session_id_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &session_id_length));
                EXPECT_EQUAL(session_id_length, S2N_TLS_SESSION_ID_MAX_LEN);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_config_free(config));
            };
        };
    };

    /* Test cipher suites list */
    {
        /* When TLS 1.3 NOT supported */
        {
            /* TLS 1.3 cipher suites NOT written by client by default */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_TRUE(conn->client_protocol_version < S2N_TLS13);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, TLS12_LENGTH_TO_CIPHER_LIST));

                uint16_t list_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &list_length));
                EXPECT_NOT_EQUAL(list_length, 0);

                uint8_t first_cipher_byte;
                for (int i = 0; i < list_length; i++) {
                    EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &first_cipher_byte));
                    EXPECT_NOT_EQUAL(first_cipher_byte, 0x13);
                    EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, 1));
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* TLS 1.3 cipher suites NOT written by client even if included in security policy */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));

                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_TRUE(conn->client_protocol_version < S2N_TLS13);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, TLS12_LENGTH_TO_CIPHER_LIST));

                uint16_t list_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &list_length));
                EXPECT_NOT_EQUAL(list_length, 0);

                uint8_t first_cipher_byte;
                for (int i = 0; i < list_length; i++) {
                    EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &first_cipher_byte));
                    EXPECT_NOT_EQUAL(first_cipher_byte, 0x13);
                    EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, 1));
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };
        };

        /* When TLS 1.3 supported */
        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());

            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            s2n_config_set_session_tickets_onoff(config, 0);

            /* TLS 1.3 cipher suites written by client */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

                struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

                EXPECT_SUCCESS(s2n_client_hello_send(conn));

                EXPECT_TRUE(conn->actual_protocol_version >= S2N_TLS13);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, TLS13_LENGTH_TO_CIPHER_LIST));

                uint16_t list_length = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &list_length));
                EXPECT_NOT_EQUAL(list_length, 0);

                uint8_t first_cipher_byte;
                int tls13_ciphers_found = 0;
                for (int i = 0; i < list_length; i++) {
                    EXPECT_SUCCESS(s2n_stuffer_read_uint8(hello_stuffer, &first_cipher_byte));
                    if (first_cipher_byte == 0x13) {
                        tls13_ciphers_found++;
                    }
                    EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, 1));
                }
                EXPECT_NOT_EQUAL(tls13_ciphers_found, 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        }

        /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV included if TLS1.2 ciphers included
         *
         *= https://tools.ietf.org/rfc/rfc5746#3.4
         *= type=test
         *# o  The client MUST include either an empty "renegotiation_info"
         *#    extension, or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling
         *#    cipher suite value in the ClientHello.
         */
        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_reset_tls13_in_test());
            const uint8_t empty_renegotiation_info_scsv[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_EMPTY_RENEGOTIATION_INFO_SCSV };

            struct {
                const char *security_policy;
                bool expect_renegotiation_info;
            } test_cases[] = {
                { .security_policy = "test_all_tls13", .expect_renegotiation_info = false },
                { .security_policy = "default_tls13", .expect_renegotiation_info = true },
                { .security_policy = "default", .expect_renegotiation_info = true },
            };

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, test_cases[i].security_policy));

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_parse_client_hello(conn));

                struct s2n_blob *cipher_suites = &conn->client_hello.cipher_suites;
                EXPECT_TRUE(cipher_suites->size > 0);

                uint8_t *iana = cipher_suites->data;
                bool found_renegotiation_info = false;
                for (size_t j = 0; j < cipher_suites->size; j += S2N_TLS_CIPHER_SUITE_LEN) {
                    if (memcmp(iana + j, empty_renegotiation_info_scsv, S2N_TLS_CIPHER_SUITE_LEN) == 0) {
                        found_renegotiation_info = true;
                    }
                }

                EXPECT_EQUAL(found_renegotiation_info, test_cases[i].expect_renegotiation_info);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }

        /* TLS1.2 cipher suites not written if QUIC enabled */
        {
            EXPECT_SUCCESS(s2n_reset_tls13_in_test());

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

            bool quic_enabled[] = { false, s2n_is_tls13_fully_supported() };

            /* TLS 1.2 cipher suites only written if QUIC not enabled */
            for (size_t i = 0; i < s2n_array_len(quic_enabled); i++) {
                config->quic_enabled = quic_enabled[i];

                struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

                EXPECT_SUCCESS(s2n_client_hello_send(conn));
                EXPECT_SUCCESS(s2n_parse_client_hello(conn));

                struct s2n_blob *cipher_suites = &conn->client_hello.cipher_suites;
                EXPECT_TRUE(cipher_suites->size > 0);

                bool tls12_cipher_found = false;
                uint8_t *iana = cipher_suites->data;
                for (size_t j = 0; j < cipher_suites->size; j += S2N_TLS_CIPHER_SUITE_LEN) {
                    /* All TLS1.3 cipher suites have IANAs starting with 0x13 */
                    if (iana[j] != 0x13) {
                        tls12_cipher_found = true;
                    }
                }

                /* TLS1.2 and QUIC are mutually exclusive */
                EXPECT_TRUE(tls12_cipher_found != quic_enabled[i]);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* Test that negotiating TLS1.2 with QUIC-enabled server fails */
    if (s2n_is_tls13_fully_supported()) {
        EXPECT_SUCCESS(s2n_reset_tls13_in_test());

        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_enable_quic(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));

        /* Succeeds when negotiating TLS1.3 */
        if (s2n_is_tls13_fully_supported()) {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io,
                    &server_conn->handshake.io, s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Fails when negotiating TLS1.2 */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all_tls12"));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io,
                    &server_conn->handshake.io, s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_recv(server_conn), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    }

    /* Test that cipher suites enforce proper highest supported versions.
     * Eg. server configs TLS 1.2 only ciphers should never negotiate TLS 1.3
     */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());

        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        {
            /* TLS 1.3 client cipher preference uses TLS13 version */
            struct s2n_connection *conn;
            const struct s2n_security_policy *security_policy;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_client_hello_send(conn));
            EXPECT_EQUAL(conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
            EXPECT_EQUAL(conn->client_protocol_version, s2n_get_highest_fully_supported_tls_version());
            EXPECT_EQUAL(conn->client_hello_version, S2N_TLS12);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        {
            /* TLS 1.2 client cipher preference uses TLS12 version */
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

            const struct s2n_security_policy *security_policy;
            POSIX_GUARD(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_client_hello_send(conn));
            EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(conn->client_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(conn->client_hello_version, S2N_TLS12);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        {
            /* TLS 1.3 client cipher preference uses TLS13 version */
            struct s2n_connection *client_conn, *server_conn;
            const struct s2n_security_policy *security_policy;

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));

            POSIX_GUARD(s2n_connection_get_security_policy(client_conn, &security_policy));
            EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_EQUAL(client_conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
            EXPECT_EQUAL(client_conn->client_protocol_version, s2n_get_highest_fully_supported_tls_version());
            EXPECT_EQUAL(client_conn->client_hello_version, S2N_TLS12);

            /* Server configured with TLS 1.2 negotiates TLS12 version */
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            struct s2n_config *server_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all_tls12"));

            POSIX_GUARD(s2n_connection_get_security_policy(server_conn, &security_policy));
            EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io, s2n_stuffer_data_available(&client_conn->handshake.io)));

            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
            EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS12);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_config_free(server_config));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* SSlv2 client hello */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;

        uint8_t sslv2_client_hello[] = {
            SSLv2_CLIENT_HELLO_PREFIX,
            SSLv2_CLIENT_HELLO_CIPHER_SUITES,
            SSLv2_CLIENT_HELLO_CHALLENGE,
        };

        int sslv2_client_hello_len = sizeof(sslv2_client_hello);

        uint8_t sslv2_client_hello_header[] = {
            SSLv2_CLIENT_HELLO_HEADER,
        };

        int sslv2_client_hello_header_len = sizeof(sslv2_client_hello_header);

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* The security policy does not need to support SSLv2.
         *
         * s2n-tls does NOT support SSLv2. However, it does accept ClientHellos in the SSLv2
         * format but advertising higher protocol versions. Clients use this strategy to
         * communicate with servers in a backwards-compatible way.
         *
         * Our test SSLv2 ClientHello advertises TLS1.2.
         * So the security policy only needs to support TLS1.2.
         */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));

        /* Send the client hello message */
        EXPECT_EQUAL(write(io_pair.client, sslv2_client_hello_header, sslv2_client_hello_header_len), sslv2_client_hello_header_len);
        EXPECT_EQUAL(write(io_pair.client, sslv2_client_hello, sslv2_client_hello_len), sslv2_client_hello_len);

        /* Verify that the sent client hello message is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_TRUE(IS_NEGOTIATED(server_conn));

        struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server_conn);

        /* Verify s2n_connection_get_client_hello returns the handle to the s2n_client_hello on the connection */
        EXPECT_EQUAL(client_hello, &server_conn->client_hello);

        uint8_t *collected_client_hello = client_hello->raw_message.data;
        uint16_t collected_client_hello_len = client_hello->raw_message.size;

        /* Verify correctly identified as SSLv2 */
        EXPECT_TRUE(client_hello->sslv2);

        /* Verify collected client hello message length */
        EXPECT_EQUAL(collected_client_hello_len, sslv2_client_hello_len);

        /* Verify the collected client hello matches what was sent */
        EXPECT_BYTEARRAY_EQUAL(collected_client_hello, sslv2_client_hello, sslv2_client_hello_len);

        /* Verify s2n_client_hello_get_raw_message_length correct */
        EXPECT_EQUAL(s2n_client_hello_get_raw_message_length(client_hello), sslv2_client_hello_len);

        uint8_t expected_cs[] = {
            SSLv2_CLIENT_HELLO_CIPHER_SUITES,
        };

        /* Verify collected cipher_suites size correct */
        EXPECT_EQUAL(client_hello->cipher_suites.size, sizeof(expected_cs));

        /* Verify collected cipher_suites correct */
        EXPECT_BYTEARRAY_EQUAL(client_hello->cipher_suites.data, expected_cs, sizeof(expected_cs));

        /* Verify s2n_client_hello_get_cipher_suites_length correct */
        EXPECT_EQUAL(s2n_client_hello_get_cipher_suites_length(client_hello), sizeof(expected_cs));

        /* Verify collected extensions size correct */
        EXPECT_EQUAL(client_hello->extensions.raw.size, 0);

        /* Verify s2n_client_hello_get_extensions_length correct */
        EXPECT_EQUAL(s2n_client_hello_get_extensions_length(client_hello), 0);

        /* Verify s2n_client_hello_get_session_id_length correct */
        uint32_t ch_session_id_length;
        EXPECT_SUCCESS(s2n_client_hello_get_session_id_length(client_hello, &ch_session_id_length));
        EXPECT_EQUAL(ch_session_id_length, 0);

        /* Free all handshake data */
        EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));

        /* Verify free_handshake resized the s2n_client_hello.raw_message stuffer back to 0 */
        EXPECT_NULL(client_hello->raw_message.data);
        EXPECT_EQUAL(client_hello->raw_message.size, 0);

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));

        /* Wipe connection */
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

        /* Verify connection_wipe resized the s2n_client_hello.raw_message stuffer back to 0 */
        EXPECT_NULL(client_hello->raw_message.data);
        EXPECT_EQUAL(client_hello->raw_message.size, 0);

        /* Verify the s2n blobs referencing cipher_suites and extensions have cleared */
        EXPECT_EQUAL(client_hello->cipher_suites.size, 0);
        EXPECT_NULL(client_hello->cipher_suites.data);
        EXPECT_EQUAL(client_hello->extensions.raw.size, 0);
        EXPECT_NULL(client_hello->extensions.raw.data);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Minimal TLS 1.2 client hello. */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        uint8_t *sent_client_hello;
        uint8_t *expected_client_hello;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00,
            0x00,
            /* Extension size */
            0x00,
            0x08,
            /* Server names len */
            0x00,
            0x06,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00,
            0x03,
            /* First server name, matches sent_server_name */
            's',
            'v',
            'r',
        };

        uint8_t server_name_extension[] = {
            /* Server names len */
            0x00,
            0x06,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00,
            0x03,
            /* First server name, matches sent_server_name */
            's',
            'v',
            'r',
        };
        int server_name_extension_len = sizeof(server_name_extension);

        size_t client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_prefix[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00,
            0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        int client_hello_prefix_len = sizeof(client_hello_prefix);
        int sent_client_hello_len = client_hello_prefix_len + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (sent_client_hello_len >> 16) & 0xff,
            (sent_client_hello_len >> 8) & 0xff,
            (sent_client_hello_len & 0xff),
        };
        int message_len = sizeof(message_header) + sent_client_hello_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Message len */
            (message_len >> 8) & 0xff,
            (message_len & 0xff),
        };

        EXPECT_NOT_NULL(sent_client_hello = malloc(sent_client_hello_len));
        EXPECT_MEMCPY_SUCCESS(sent_client_hello, client_hello_prefix, client_hello_prefix_len);
        EXPECT_MEMCPY_SUCCESS(sent_client_hello + client_hello_prefix_len, client_extensions, client_extensions_len);

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        /* Security policy must allow cipher suite hard coded into client hello */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all"));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Verify s2n_connection_get_client_hello returns null if client hello not yet processed */
        EXPECT_NULL(s2n_connection_get_client_hello(server_conn));

        uint8_t *ext_data;
        EXPECT_NOT_NULL(ext_data = malloc(server_name_extension_len));
        /* Verify we don't get extension and it's length when client hello is not yet processed */
        EXPECT_FAILURE(s2n_client_hello_get_extension_length(s2n_connection_get_client_hello(server_conn), S2N_EXTENSION_SERVER_NAME));
        EXPECT_FAILURE(s2n_client_hello_get_extension_by_id(s2n_connection_get_client_hello(server_conn), S2N_EXTENSION_SERVER_NAME, ext_data, server_name_extension_len));
        free(ext_data);
        ext_data = NULL;

        /* Send the client hello message */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, sent_client_hello, sent_client_hello_len), sent_client_hello_len);

        /* Verify that the sent client hello message is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server_conn);

        /* Verify correctly identified as NOT sslv2 */
        EXPECT_FALSE(client_hello->sslv2);

        /* Verify s2n_connection_get_client_hello returns the handle to the s2n_client_hello on the connection */
        EXPECT_EQUAL(client_hello, &server_conn->client_hello);

        uint8_t *collected_client_hello = client_hello->raw_message.data;
        uint16_t collected_client_hello_len = client_hello->raw_message.size;

        /* Verify collected client hello message length */
        EXPECT_EQUAL(collected_client_hello_len, sent_client_hello_len);

        /* Verify the collected client hello has client random zero-ed out */
        uint8_t client_random_offset = S2N_TLS_PROTOCOL_VERSION_LEN;
        uint8_t expected_client_random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
        EXPECT_BYTEARRAY_EQUAL(collected_client_hello + client_random_offset, expected_client_random, S2N_TLS_RANDOM_DATA_LEN);

        /* Verify the collected client hello matches what was sent except for the zero-ed client random */
        EXPECT_NOT_NULL(expected_client_hello = malloc(sent_client_hello_len));
        EXPECT_MEMCPY_SUCCESS(expected_client_hello, sent_client_hello, sent_client_hello_len);
        POSIX_CHECKED_MEMSET(expected_client_hello + client_random_offset, 0, S2N_TLS_RANDOM_DATA_LEN);
        EXPECT_BYTEARRAY_EQUAL(collected_client_hello, expected_client_hello, sent_client_hello_len);

        /* Verify s2n_client_hello_get_raw_message_length correct */
        EXPECT_EQUAL(s2n_client_hello_get_raw_message_length(client_hello), sent_client_hello_len);

        uint8_t *raw_ch_out;

        /* Verify s2n_client_hello_get_raw_message retrieves the full message when its len <= max_len */
        EXPECT_TRUE(collected_client_hello_len < S2N_LARGE_RECORD_LENGTH);
        EXPECT_NOT_NULL(raw_ch_out = malloc(S2N_LARGE_RECORD_LENGTH));
        EXPECT_EQUAL(sent_client_hello_len, s2n_client_hello_get_raw_message(client_hello, raw_ch_out, S2N_LARGE_RECORD_LENGTH));
        EXPECT_BYTEARRAY_EQUAL(raw_ch_out, expected_client_hello, sent_client_hello_len);
        free(raw_ch_out);
        raw_ch_out = NULL;

        /* Verify s2n_client_hello_get_raw_message retrieves truncated message when its len > max_len */
        EXPECT_TRUE(collected_client_hello_len > 0);
        uint32_t max_len = collected_client_hello_len - 1;
        EXPECT_NOT_NULL(raw_ch_out = malloc(max_len));
        EXPECT_EQUAL(max_len, s2n_client_hello_get_raw_message(client_hello, raw_ch_out, max_len));
        EXPECT_BYTEARRAY_EQUAL(raw_ch_out, expected_client_hello, max_len);
        free(raw_ch_out);
        raw_ch_out = NULL;

        uint8_t expected_cs[] = { 0x00, 0x3C };

        /* Verify collected cipher_suites size correct */
        EXPECT_EQUAL(client_hello->cipher_suites.size, sizeof(expected_cs));

        /* Verify collected cipher_suites correct */
        EXPECT_BYTEARRAY_EQUAL(client_hello->cipher_suites.data, expected_cs, sizeof(expected_cs));

        /* Verify s2n_client_hello_get_cipher_suites_length correct */
        EXPECT_EQUAL(s2n_client_hello_get_cipher_suites_length(client_hello), sizeof(expected_cs));

        /* Verify s2n_client_hello_get_cipher_suites correct */
        uint8_t *cs_out;

        /* Verify s2n_client_hello_get_cipher_suites retrieves the full cipher_suites when its len <= max_len */
        EXPECT_TRUE(client_hello->cipher_suites.size < S2N_LARGE_RECORD_LENGTH);
        EXPECT_NOT_NULL(cs_out = malloc(S2N_LARGE_RECORD_LENGTH));
        EXPECT_EQUAL(sizeof(expected_cs), s2n_client_hello_get_cipher_suites(client_hello, cs_out, S2N_LARGE_RECORD_LENGTH));
        EXPECT_BYTEARRAY_EQUAL(cs_out, client_hello->cipher_suites.data, sizeof(expected_cs));
        free(cs_out);
        cs_out = NULL;

        /* Verify s2n_client_hello_get_cipher_suites retrieves truncated message when cipher_suites len > max_len */
        max_len = sizeof(expected_cs) - 1;
        EXPECT_TRUE(max_len > 0);

        EXPECT_NOT_NULL(cs_out = malloc(max_len));
        EXPECT_EQUAL(max_len, s2n_client_hello_get_cipher_suites(client_hello, cs_out, max_len));
        EXPECT_BYTEARRAY_EQUAL(cs_out, client_hello->cipher_suites.data, max_len);
        free(cs_out);
        cs_out = NULL;

        /* Verify collected extensions size correct */
        EXPECT_EQUAL(client_hello->extensions.raw.size, client_extensions_len);

        /* Verify collected extensions correct */
        EXPECT_BYTEARRAY_EQUAL(client_hello->extensions.raw.data, client_extensions, client_extensions_len);

        /* Verify s2n_client_hello_get_extensions_length correct */
        EXPECT_EQUAL(s2n_client_hello_get_extensions_length(client_hello), client_extensions_len);

        /* Verify s2n_client_hello_get_extensions correct */
        uint8_t *extensions_out;

        /* Verify s2n_client_hello_get_extensions retrieves the full cipher_suites when its len <= max_len */
        EXPECT_TRUE(client_hello->extensions.raw.size < S2N_LARGE_RECORD_LENGTH);
        EXPECT_NOT_NULL(extensions_out = malloc(S2N_LARGE_RECORD_LENGTH));
        EXPECT_EQUAL(client_extensions_len, s2n_client_hello_get_extensions(client_hello, extensions_out, S2N_LARGE_RECORD_LENGTH));
        EXPECT_BYTEARRAY_EQUAL(extensions_out, client_extensions, client_extensions_len);
        free(extensions_out);
        extensions_out = NULL;

        /* Verify s2n_client_hello_get_extensions retrieves truncated message when cipher_suites len > max_len */
        max_len = client_extensions_len - 1;
        EXPECT_TRUE(max_len > 0);

        EXPECT_NOT_NULL(extensions_out = malloc(max_len));
        EXPECT_EQUAL(max_len, s2n_client_hello_get_extensions(client_hello, extensions_out, max_len));
        EXPECT_BYTEARRAY_EQUAL(extensions_out, client_hello->extensions.raw.data, max_len);
        free(extensions_out);
        extensions_out = NULL;

        /* Verify server name extension and it's length are returned correctly */
        EXPECT_EQUAL(s2n_client_hello_get_extension_length(client_hello, S2N_EXTENSION_SERVER_NAME), server_name_extension_len);
        EXPECT_NOT_NULL(ext_data = malloc(server_name_extension_len));
        EXPECT_EQUAL(s2n_client_hello_get_extension_by_id(client_hello, S2N_EXTENSION_SERVER_NAME, ext_data, server_name_extension_len), server_name_extension_len);
        EXPECT_BYTEARRAY_EQUAL(ext_data, server_name_extension, server_name_extension_len);
        free(ext_data);
        ext_data = NULL;

        /* Verify server name extension is truncated if extension_size > max_len */
        EXPECT_NOT_NULL(ext_data = malloc(server_name_extension_len - 1));
        EXPECT_EQUAL(s2n_client_hello_get_extension_by_id(client_hello, S2N_EXTENSION_SERVER_NAME, ext_data, server_name_extension_len - 1), server_name_extension_len - 1);
        EXPECT_BYTEARRAY_EQUAL(ext_data, server_name_extension, server_name_extension_len - 1);
        free(ext_data);
        ext_data = NULL;

        /* Verify get extension and it's length calls for a non-existing extension type */
        EXPECT_EQUAL(s2n_client_hello_get_extension_length(client_hello, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY), 0);
        EXPECT_NOT_NULL(ext_data = malloc(server_name_extension_len));
        EXPECT_EQUAL(s2n_client_hello_get_extension_by_id(client_hello, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, ext_data, server_name_extension_len), 0);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_EXTENSION_NOT_RECEIVED);
        free(ext_data);
        ext_data = NULL;

        /* Verify server name extension exists */
        bool extension_exists = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(client_hello, S2N_EXTENSION_SERVER_NAME, &extension_exists));
        EXPECT_TRUE(extension_exists);

        /* Verify expected result for non-existing extension */
        extension_exists = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(client_hello, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, &extension_exists));
        EXPECT_FALSE(extension_exists);

        /* Verify s2n_client_hello_get_session_id is what we received in ClientHello */
        uint8_t expected_ch_session_id[] = { ZERO_TO_THIRTY_ONE };
        uint8_t ch_session_id[sizeof(expected_ch_session_id)];
        uint32_t ch_session_id_length;
        EXPECT_SUCCESS(s2n_client_hello_get_session_id_length(client_hello, &ch_session_id_length));
        EXPECT_EQUAL(ch_session_id_length, sizeof(ch_session_id));
        EXPECT_SUCCESS(s2n_client_hello_get_session_id(client_hello, ch_session_id, &ch_session_id_length, sizeof(ch_session_id)));
        EXPECT_EQUAL(ch_session_id_length, sizeof(ch_session_id));
        EXPECT_BYTEARRAY_EQUAL(ch_session_id, expected_ch_session_id, sizeof(expected_ch_session_id));

        /* Verify s2n_connection_get_session_id is different from the one we received in ClientHello, as we generated a new one in ServerHello */
        uint8_t conn_session_id[sizeof(expected_ch_session_id)];
        EXPECT_EQUAL(s2n_connection_get_session_id_length(server_conn), sizeof(conn_session_id));
        EXPECT_SUCCESS(s2n_connection_get_session_id(server_conn, conn_session_id, sizeof(conn_session_id)));
        EXPECT_BYTEARRAY_NOT_EQUAL(conn_session_id, ch_session_id, sizeof(expected_ch_session_id));

        /* Free all handshake data */
        EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));

        /* Verify free_handshake resized the s2n_client_hello.raw_message stuffer back to 0 */
        EXPECT_NULL(client_hello->raw_message.data);
        EXPECT_EQUAL(client_hello->raw_message.size, 0);

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));

        /* Wipe connection */
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

        /* Verify connection_wipe resized the s2n_client_hello.raw_message stuffer back to 0 */
        EXPECT_NULL(client_hello->raw_message.data);
        EXPECT_EQUAL(client_hello->raw_message.size, 0);

        /* Verify the s2n blobs referencing cipher_suites and extensions have cleared */
        EXPECT_EQUAL(client_hello->cipher_suites.size, 0);
        EXPECT_NULL(client_hello->cipher_suites.data);
        EXPECT_EQUAL(client_hello->extensions.raw.size, 0);
        EXPECT_NULL(client_hello->extensions.raw.data);

        /* Verify the connection is successfully reused after connection_wipe */

        /* Re-configure connection */
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        /* Security policy must allow cipher suite hard coded into client hello */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all"));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Recreate config */
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Re-send the client hello message */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, sent_client_hello, sent_client_hello_len), sent_client_hello_len);

        /* Verify that the sent client hello message is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        /* Verify the collected client hello on the reused connection matches the expected client hello */
        client_hello = s2n_connection_get_client_hello(server_conn);
        collected_client_hello = client_hello->raw_message.data;
        EXPECT_BYTEARRAY_EQUAL(collected_client_hello, expected_client_hello, sent_client_hello_len);

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        free(expected_client_hello);
        free(sent_client_hello);
    };

    /* Client hello api with NULL inputs */
    {
        uint32_t len = 128;
        uint8_t *out;
        EXPECT_NOT_NULL(out = malloc(len));

        EXPECT_FAILURE(s2n_client_hello_get_raw_message_length(NULL));
        EXPECT_FAILURE(s2n_client_hello_get_raw_message(NULL, out, len));
        EXPECT_FAILURE(s2n_client_hello_get_cipher_suites_length(NULL));
        EXPECT_FAILURE(s2n_client_hello_get_cipher_suites(NULL, out, len));
        EXPECT_FAILURE(s2n_client_hello_get_extensions_length(NULL));
        EXPECT_FAILURE(s2n_client_hello_get_extensions(NULL, out, len));
        EXPECT_FAILURE(s2n_client_hello_get_extension_length(NULL, S2N_EXTENSION_SERVER_NAME));
        EXPECT_FAILURE(s2n_client_hello_get_extension_by_id(NULL, S2N_EXTENSION_SERVER_NAME, out, len));
        free(out);
        out = NULL;

        bool exists = false;
        EXPECT_FAILURE(s2n_client_hello_has_extension(NULL, S2N_EXTENSION_SERVER_NAME, &exists));
        EXPECT_FALSE(exists);
    };

    /* test_weird_client_hello_version() */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        uint8_t *sent_client_hello;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00,
            0x00,
            /* Extension size */
            0x00,
            0x08,
            /* Server names len */
            0x00,
            0x06,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00,
            0x03,
            /* First server name, matches sent_server_name */
            's',
            'v',
            'r',
        };

        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_prefix[] = {
            /* Protocol version TLS ??? */
            0xFF,
            0xFF,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00,
            0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        int client_hello_prefix_len = sizeof(client_hello_prefix);
        int sent_client_hello_len = client_hello_prefix_len + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (sent_client_hello_len >> 16) & 0xff,
            (sent_client_hello_len >> 8) & 0xff,
            (sent_client_hello_len & 0xff),
        };
        int message_len = sizeof(message_header) + sent_client_hello_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Message len */
            (message_len >> 8) & 0xff,
            (message_len & 0xff),
        };

        EXPECT_NOT_NULL(sent_client_hello = malloc(sent_client_hello_len));
        EXPECT_MEMCPY_SUCCESS(sent_client_hello, client_hello_prefix, client_hello_prefix_len);
        EXPECT_MEMCPY_SUCCESS(sent_client_hello + client_hello_prefix_len, client_extensions, client_extensions_len);

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        /* Security policy must allow cipher suite hard coded into client hello */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all"));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello message */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, sent_client_hello, sent_client_hello_len), sent_client_hello_len);

        /* Verify that the sent client hello message is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);
        /* Client sent an invalid legacy protocol version. We should still have negotiate the maximum value(TLS1.2) */
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        s2n_connection_free(server_conn);
        s2n_config_free(server_config);
        free(sent_client_hello);
    };

    {
        struct s2n_cipher_suite *client_cipher_suites[] = {
            &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
        };

        struct s2n_cipher_preferences client_cipher_preferences = {
            .count = s2n_array_len(client_cipher_suites),
            .suites = client_cipher_suites,
        };

        const struct s2n_signature_scheme *const client_sig_scheme_pref_list[] = {
            &s2n_rsa_pkcs1_sha1,

            /* Intentionally do not send and ECDSA SignatureScheme in the Client Hello. This is malformed since the
             * Client's only Ciphersuite uses ECDSA, meaning that technically the Server could reject it, but there are
             * some clients that send this form of malformed Client Hello's in the wild. So ensure we are compatible
             * with them by assuming that the Client does support ECDSA, even though it's missing from the ClientHello.
             */

            /* &s2n_ecdsa_sha1, */
        };

        struct s2n_signature_preferences client_signature_preferences = {
            .count = s2n_array_len(client_sig_scheme_pref_list),
            .signature_schemes = client_sig_scheme_pref_list,
        };

        struct s2n_security_policy client_security_policy = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &client_cipher_preferences,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &client_signature_preferences,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };

        EXPECT_TRUE(client_cipher_suites[0]->available);

        struct s2n_cert_chain_and_key *ecdsa_cert_chain;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

        char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

        /* Create Configs */
        struct s2n_config *server_config, *client_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert_chain));

        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
        server_config->security_policy = &security_policy_20190214;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        client_config->security_policy = &client_security_policy;

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        /* Create connection */
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* We have to update the client's security policy after it sends the ClientHello.
         * The client sends all signature algorithms in its security policy, and
         * won't accept any signature algorithm it receives that's not in its security policy.
         * So we need to change the security policy between sending and receiving.
         */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_HELLO));
        client_config->security_policy = &security_policy_20190214;
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_EQUAL(server_conn->secure->cipher_suite, &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha);
        EXPECT_EQUAL(client_conn->secure->cipher_suite, &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha);
        EXPECT_EQUAL(server_conn->handshake_params.server_cert_sig_scheme->sig_alg, S2N_SIGNATURE_ECDSA);
        EXPECT_EQUAL(server_conn->handshake_params.server_cert_sig_scheme->hash_alg, S2N_HASH_SHA1);
        EXPECT_EQUAL(client_conn->handshake_params.server_cert_sig_scheme->sig_alg, S2N_SIGNATURE_ECDSA);
        EXPECT_EQUAL(client_conn->handshake_params.server_cert_sig_scheme->hash_alg, S2N_HASH_SHA1);

        /* Free the data */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_chain));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* s2n_client_hello_recv should fail when reading an SSLv2 client hello during a hello retry handshake */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        /* Handshake is hello retry and TLS1.3 was negotiated */
        server_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_OK(s2n_handshake_type_set_tls13_flag(server_conn, HELLO_RETRY_REQUEST));

        /* Second client hello has version SSLv2 */
        server_conn->client_hello_version = S2N_SSLv2;

        /* Mock having some data in the client hello */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&server_conn->handshake.io, 100));

        EXPECT_FAILURE_WITH_ERRNO(s2n_parse_client_hello(server_conn), S2N_ERR_SAFETY);
    };

    /* Test s2n_client_hello_parse_message
     *
     * Comparing ClientHellos produced by connection IO parsing vs
     * produced by s2n_client_hello_parse_message is difficult, but we can
     * use JA3 fingerprints as an approximation. See s2n_fingerprint_ja3_test.c
     */
    {
        const char *security_policies[] = { "default", "default_tls13", "test_all" };

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Test: Can parse ClientHellos sent by the s2n client */
        for (size_t i = 0; i < s2n_array_len(security_policies); i++) {
            const char *security_policy = security_policies[i];

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, security_policy));

            EXPECT_SUCCESS(s2n_handshake_write_header(&client->handshake.io, TLS_CLIENT_HELLO));
            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_handshake_finish_header(&client->handshake.io));

            uint32_t raw_size = s2n_stuffer_data_available(&client->handshake.io);
            EXPECT_NOT_EQUAL(raw_size, 0);
            uint8_t *raw = s2n_stuffer_raw_read(&client->handshake.io, raw_size);
            EXPECT_NOT_NULL(raw);

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL, s2n_client_hello_free);
            EXPECT_NOT_NULL(client_hello = s2n_client_hello_parse_message(raw, raw_size));
            EXPECT_TRUE(client_hello->alloced);
        };

        /* Test: Rejects invalid ClientHellos
         *
         * This test is important to verify that no memory is leaked when parsing fails.
         */
        {
            struct s2n_client_hello *client_hello = NULL;

            uint8_t wrong_message_type[50] = { 0x02, 0x00, 0x00, 1 };
            client_hello = s2n_client_hello_parse_message(wrong_message_type, sizeof(wrong_message_type));
            EXPECT_NULL(client_hello);
            EXPECT_EQUAL(s2n_errno, S2N_ERR_BAD_MESSAGE);

            uint8_t wrong_message_size[50] = { 0x01, 0x00, 0x00, UINT8_MAX };
            client_hello = s2n_client_hello_parse_message(wrong_message_size, sizeof(wrong_message_size));
            EXPECT_NULL(client_hello);
            EXPECT_EQUAL(s2n_errno, S2N_ERR_BAD_MESSAGE);

            uint8_t too_short[5] = { 0x01, 0x00, 0x00, 1 };
            client_hello = s2n_client_hello_parse_message(too_short, sizeof(too_short));
            EXPECT_NULL(client_hello);
            EXPECT_EQUAL(s2n_errno, S2N_ERR_STUFFER_OUT_OF_DATA);

            uint8_t all_zeroes[50] = { 0x01, 0x00, 0x00, 46 };
            client_hello = s2n_client_hello_parse_message(all_zeroes, sizeof(all_zeroes));
            EXPECT_NULL(client_hello);
            EXPECT_EQUAL(s2n_errno, S2N_ERR_BAD_MESSAGE);
        };

        /* Test: Rejects SSLv2 */
        {
            uint8_t sslv2_client_hello[] = {
                SSLv2_CLIENT_HELLO_HEADER,
                SSLv2_CLIENT_HELLO_PREFIX,
                SSLv2_CLIENT_HELLO_CIPHER_SUITES,
                SSLv2_CLIENT_HELLO_CHALLENGE,
            };

            /* Try parsing variations on the complete record vs just the message.
             * The sslv2 record header is technically the first two bytes,
             * but s2n-tls usually starts parsing after the first five bytes.
             */
            for (size_t i = 0; i <= S2N_TLS_RECORD_HEADER_LENGTH; i++) {
                struct s2n_client_hello *client_hello = s2n_client_hello_parse_message(
                        sslv2_client_hello + i, sizeof(sslv2_client_hello) - i);
                EXPECT_NULL(client_hello);
                EXPECT_EQUAL(s2n_errno, S2N_ERR_BAD_MESSAGE);
            }

            /* Sanity check: s2n accepts the test sslv2 message via the connection */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all"));

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server->header_in,
                        sslv2_client_hello, S2N_TLS_RECORD_HEADER_LENGTH));
                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server->in,
                        sslv2_client_hello + S2N_TLS_RECORD_HEADER_LENGTH,
                        sizeof(sslv2_client_hello) - S2N_TLS_RECORD_HEADER_LENGTH));

                EXPECT_FALSE(server->client_hello.sslv2);
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                EXPECT_OK(s2n_negotiate_until_message(server, &blocked, SERVER_HELLO));
                EXPECT_TRUE(server->client_hello.sslv2);
                EXPECT_FALSE(server->client_hello.alloced);
            }
        };
    };

    /* Test s2n_client_hello_free */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_free(NULL), S2N_ERR_NULL);

        /* Test: Accepts but ignores NULL / already freed */
        {
            struct s2n_client_hello *client_hello = NULL;
            for (size_t i = 0; i < 3; i++) {
                EXPECT_SUCCESS(s2n_client_hello_free(&client_hello));
                EXPECT_NULL(client_hello);
            }
        };

        /* Test: Errors on client hello associated with a connection */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
            EXPECT_NOT_NULL(client_hello);
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_hello_free(&client_hello), S2N_ERR_INVALID_ARGUMENT);
            EXPECT_NOT_NULL(s2n_connection_get_client_hello(server));
            EXPECT_NOT_EQUAL(server->client_hello.raw_message.size, 0);
        };

        /* Test: Frees client hello from raw message */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);

            EXPECT_SUCCESS(s2n_handshake_write_header(&client->handshake.io, TLS_CLIENT_HELLO));
            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_handshake_finish_header(&client->handshake.io));

            uint32_t raw_size = s2n_stuffer_data_available(&client->handshake.io);
            EXPECT_NOT_EQUAL(raw_size, 0);
            uint8_t *raw = s2n_stuffer_raw_read(&client->handshake.io, raw_size);
            EXPECT_NOT_NULL(raw);

            struct s2n_client_hello *client_hello = s2n_client_hello_parse_message(
                    raw, raw_size);
            EXPECT_NOT_NULL(client_hello);

            for (size_t i = 0; i < 3; i++) {
                EXPECT_SUCCESS(s2n_client_hello_free(&client_hello));
                EXPECT_NULL(client_hello);
            }
        };
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_chain_and_key));
    END_TEST();
    return 0;
}
