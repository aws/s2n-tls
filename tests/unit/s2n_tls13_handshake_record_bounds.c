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

#include <stdint.h>
#include <stdlib.h>

#include "api/s2n.h"

#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "stuffer/s2n_stuffer.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_tls13_handshake.c"
#include "tls/s2n_handshake_transcript.c"

#define S2N_SECRET_TYPE_COUNT 5
#define S2N_TEST_PSK_COUNT 10

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /*
     *= https://tools.ietf.org/rfc/rfc8446#5.1
     *= type=test
     *# Handshake messages MAY be coalesced into a single TLSPlaintext record
     *# or fragmented across several records, provided that:
     */
    
    /*
     *= https://tools.ietf.org/rfc/rfc8446#5.1
     *= type=TEST
     *# -  Handshake messages MUST NOT span key changes.  Implementations
     *#    MUST verify that all messages immediately preceding a key change
     *#    align with a record boundary; if not, then they MUST terminate the
     *#    connection with an "unexpected_message" alert.
     */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        struct s2n_config *server_config, *client_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        uint8_t *cert_chain = NULL;
        uint8_t *private_key = NULL;
        uint32_t cert_chain_len = 0;
        uint32_t private_key_len = 0;

        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_KEY, private_key, &private_key_len, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_cert_chain_and_key *default_cert;
        EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(default_cert, cert_chain, cert_chain_len, private_key, private_key_len));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_stuffer client_to_server;
        struct s2n_stuffer server_to_client;

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        S2N_BLOB_FROM_HEX(seq_0, "0000000000000000");
        S2N_BLOB_FROM_HEX(seq_1, "0000000000000001");

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        /* Client sends ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);

        /* Write a client hello */
        EXPECT_SUCCESS(s2n_handshake_write_header(&client_conn->handshake.io, TLS_CLIENT_HELLO));
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_handshake_finish_header(&client_conn->handshake.io));

        /* Write an extra message to this record */
        uint8_t blob_data[500];
        struct s2n_blob blob;
        EXPECT_SUCCESS(s2n_blob_init(&blob, blob_data, 500));
        struct s2n_stuffer io;
        EXPECT_SUCCESS(s2n_stuffer_init(&io, &blob));
        EXPECT_SUCCESS(s2n_handshake_write_header(&io, TLS_CERTIFICATE));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&io, 0));
        EXPECT_SUCCESS(s2n_send_empty_cert_chain(&io));
        EXPECT_SUCCESS(s2n_handshake_finish_header(&io));

        EXPECT_SUCCESS(s2n_stuffer_copy(&io, &client_conn->handshake.io, s2n_stuffer_data_available(&io)));

        /* After loading up handshake.io write it out.  */        
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);

        s2n_tls13_connection_keys(server_secrets_0, server_conn);
        EXPECT_EQUAL(server_secrets_0.size, 0);

        EXPECT_EQUAL(server_conn->handshake.handshake_type, INITIAL);

        /* Server reads ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        EXPECT_FAILURE_WITH_ERRNO (s2n_handshake_read_io(server_conn), S2N_ERR_BAD_MESSAGE);

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
    }

    /* Try to construct a situation in which a bad implemention might not align
     * these messages with a record boundary. We send the Client hello and then
     * ensure we are at a record boundary by checking the out messages.
     *
     *= https://tools.ietf.org/rfc/rfc8446#5.1
     *= type=test
     *# Because the
     *# ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
     *# messages can immediately precede a key change, implementations
     *# MUST send these messages in alignment with a record boundary.
     */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        struct s2n_config *server_config, *client_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        uint8_t *cert_chain = NULL;
        uint8_t *private_key = NULL;
        uint32_t cert_chain_len = 0;
        uint32_t private_key_len = 0;

        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_KEY, private_key, &private_key_len, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_cert_chain_and_key *default_cert;
        EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(default_cert, cert_chain, cert_chain_len, private_key, private_key_len));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_stuffer client_to_server;
        struct s2n_stuffer server_to_client;

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        S2N_BLOB_FROM_HEX(seq_0, "0000000000000000");
        S2N_BLOB_FROM_HEX(seq_1, "0000000000000001");

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        /* Client sends ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);      
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

        EXPECT_TRUE(!s2n_stuffer_data_available(&client_conn->in));
        EXPECT_TRUE(!s2n_stuffer_data_available(&client_conn->out));

        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);

        s2n_tls13_connection_keys(server_secrets_0, server_conn);
        EXPECT_EQUAL(server_secrets_0.size, 0);

        EXPECT_EQUAL(server_conn->handshake.handshake_type, INITIAL);

        /* Server reads ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

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
    }

    END_TEST();
    return 0;
}
