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
#include "tls/s2n_client_hello.c"

/* The server will always prefer to negotiate an application protocol with 
 * the ALPN extension. This callback wipes the ALPN extension from the client
 * hello and forces the server to negotiate a protocol using the NPN extension 
 * instead. */
static int s2n_wipe_alpn_ext(struct s2n_connection *conn, void *ctx)
{
    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    POSIX_ENSURE_REF(client_hello);
    s2n_parsed_extension *parsed_extension = NULL;
    POSIX_GUARD(s2n_client_hello_get_parsed_extension(S2N_EXTENSION_ALPN, &client_hello->extensions, &parsed_extension));
    POSIX_ENSURE_REF(parsed_extension);
    POSIX_GUARD(s2n_blob_zero(&parsed_extension->extension));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const char *protocols[] = { "http/1.1", "spdy/1", "spdy/2" };
    const uint8_t protocols_count = s2n_array_len(protocols);

    /* Set up connections */
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(server_conn);
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(client_conn);

    /* Set up config */
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
    config->npn_supported = true;

    /* Set up config that wipes ALPN extension */
    DEFER_CLEANUP(struct s2n_config *npn_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(npn_config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(npn_config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(npn_config, "default"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(npn_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_protocol_preferences(npn_config, protocols, protocols_count));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(npn_config, s2n_wipe_alpn_ext, NULL));
    npn_config->npn_supported = true;

    EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
    EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

    /* Client and server both support NPN. ALPN is negotiated since it is also
     * supported and the server prefers ALPN. */
    {
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Server prefers ALPN over NPN */
        EXPECT_FALSE(IS_NPN_HANDSHAKE(server_conn));
        EXPECT_FALSE(IS_NPN_HANDSHAKE(client_conn));

        /* ALPN has negotiated a protocol */
        EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        EXPECT_NOT_NULL(s2n_get_application_protocol(server_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(server_conn), protocols[0], strlen(protocols[0]));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* Client and server both support NPN. Wipe ALPN with the Client Hello callback so only NPN is received.
     * NPN is negotiated and not ALPN. */
    {
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, npn_config));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_TRUE(IS_NPN_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_NPN_HANDSHAKE(client_conn));

        /* NPN has negotiated a protocol */
        EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        EXPECT_NOT_NULL(s2n_get_application_protocol(server_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(server_conn), protocols[0], strlen(protocols[0]));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* Client and server both support NPN, however, they have no protocols in common.
     * Connection negotiates client's top protocol. */
    {
        /* Config with different protocols */
        const char *server_protocols[] = { "h2", "h3" };
        const uint8_t server_protocols_count = s2n_array_len(server_protocols);
        DEFER_CLEANUP(struct s2n_config *different_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(different_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(different_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(different_config, "default"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(different_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(different_config, server_protocols, server_protocols_count));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(different_config, s2n_wipe_alpn_ext, NULL));
        different_config->npn_supported = true;
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, different_config));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_TRUE(IS_NPN_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_NPN_HANDSHAKE(client_conn));

        /* Client-preference protocol is chosen since server and client have no mutually supported protocols. */
        EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        EXPECT_NOT_NULL(s2n_get_application_protocol(server_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(server_conn), protocols[0], strlen(protocols[0]));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    END_TEST();
}
