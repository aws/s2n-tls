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

#include "crypto/s2n_rsa_signing.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/extensions/s2n_server_alpn.h"
#include "tls/extensions/s2n_server_max_fragment_length.h"
#include "tls/extensions/s2n_server_server_name.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test s2n_encrypted_extensions_send */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_encrypted_extensions_send(NULL));

        /* Should fail for pre-TLS1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            /* Fails for TLS1.2 */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE_WITH_ERRNO(s2n_encrypted_extensions_send(conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.3 */
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Should send no extensions by default */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            uint16_t extension_list_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_list_size));
            EXPECT_EQUAL(extension_list_size, 0);
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Should send a requested extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            uint16_t extension_list_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_list_size));
            EXPECT_NOT_EQUAL(extension_list_size, 0);
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), extension_list_size);

            uint16_t extension_type;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_type));
            EXPECT_EQUAL(extension_type, s2n_server_server_name_extension.iana_value);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_encrypted_extensions_recv */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_encrypted_extensions_recv(NULL));

        /* Should fail for pre-TLS1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            /* Fails for TLS1.2 */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE_WITH_ERRNO(s2n_encrypted_extensions_recv(conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.3 */
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Should parse an empty list */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            /* Parse no data */
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            /* Parse explicitly empty list */
            EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, conn, stuffer));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            /* Parse empty result of default s2n_encrypted_extensions_send */
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Should parse a requested extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            /* Reset server_name_used */
            conn->server_name_used = 0;

            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);
            EXPECT_EQUAL(conn->server_name_used, 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Functional: Unencrypted EncryptedExtensions rejected */
    if (s2n_is_tls13_fully_supported()) {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        /* Create IO stuffers */
        DEFER_CLEANUP(struct s2n_stuffer client_to_server = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_to_client = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        /* Do handshake up until EncryptedExtensions */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, ENCRYPTED_EXTENSIONS));
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), ENCRYPTED_EXTENSIONS);

        /* Verify that the EncryptedExtension message would normally be encrypted */
        EXPECT_EQUAL(server_conn->server, server_conn->secure);

        /* Force the server to disable encryption for the EncryptedExtensions message */
        server_conn->server = server_conn->initial;

        /* Enable an extension to ensure the message is long enough to resemble an encrypted record.
         * If the message is too short, we fail without even attempting decryption and this error
         * is difficult to distinguish from other S2N_ERR_BAD_MESSAGE cases.
         */
        uint8_t long_alpn[] = "httttttttttttttttttttps";
        EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(server_conn));
        EXPECT_MEMCPY_SUCCESS(server_conn->application_protocol, long_alpn, sizeof(long_alpn));

        /* Reset the stuffer, potentially wiping any pending CCS messages.
         * We don't need the complication of accidentally rereading old messages.
         */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_to_client));

        /* Write unencrypted EncryptedExtensions message */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), ENCRYPTED_EXTENSIONS);
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_NOT_EQUAL(s2n_conn_get_current_message_type(server_conn), ENCRYPTED_EXTENSIONS);

        /* Verify message is unencrypted handshake message instead of
         * encrypted APPLICATION_DATA message.
         */
        uint8_t type = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &type));
        EXPECT_EQUAL(type, TLS_HANDSHAKE); /* Record type not APPLICATION_DATA */
        EXPECT_SUCCESS(s2n_stuffer_reread(&server_to_client));
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&server_to_client, S2N_TLS_RECORD_HEADER_LENGTH));
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &type));
        EXPECT_EQUAL(type, TLS_ENCRYPTED_EXTENSIONS); /* Actual handshake type not encrypted */
        EXPECT_SUCCESS(s2n_stuffer_reread(&server_to_client));

        /* Client fails to parse the EncryptedExtensions */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(client_conn, &blocked), S2N_ERR_DECRYPT);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
