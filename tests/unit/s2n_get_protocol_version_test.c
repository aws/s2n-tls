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
#include "tls/s2n_tls.h"

struct s2n_override_extension_ctx {
    struct s2n_blob extension_blob;
    int invoked_count;
};

static int s2n_override_supported_versions_cb(struct s2n_connection *conn, void *ctx)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(ctx);

    struct s2n_override_extension_ctx *context = (struct s2n_override_extension_ctx *) ctx;
    context->invoked_count += 1;

    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    EXPECT_NOT_NULL(client_hello);

    s2n_extension_type_id supported_versions_id = 0;
    EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(S2N_EXTENSION_SUPPORTED_VERSIONS, &supported_versions_id));

    s2n_parsed_extension *supported_versions_extension = &client_hello->extensions.parsed_extensions[supported_versions_id];
    supported_versions_extension->extension_type = S2N_EXTENSION_SUPPORTED_VERSIONS;
    supported_versions_extension->extension = context->extension_blob;

    return S2N_SUCCESS;
}

S2N_RESULT s2n_write_protocol_version(struct s2n_stuffer *stuffer, uint8_t version)
{
    RESULT_ENSURE_REF(stuffer);

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = { 0 };
    protocol_version[0] = version / 10;
    protocol_version[1] = version % 10;

    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(stuffer, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_write_test_supported_versions_extension(struct s2n_blob *supported_versions_blob, uint8_t version)
{
    RESULT_ENSURE_REF(supported_versions_blob);

    struct s2n_stuffer supported_versions_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&supported_versions_stuffer, supported_versions_blob));

    /* Write the length byte. */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, 2));
    /* Write the supported version. */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, version / 10));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, version % 10));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_write_malformed_supported_versions_extension(struct s2n_blob *supported_versions_blob)
{
    RESULT_ENSURE_REF(supported_versions_blob);

    struct s2n_stuffer supported_versions_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&supported_versions_stuffer, supported_versions_blob));

    /* Write an invalid length byte. */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, 11));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Safety */
    {
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_client_protocol_version(NULL), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_client_hello_version(NULL), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_server_protocol_version(NULL), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_actual_protocol_version(NULL), S2N_ERR_NULL);
    }

    /* Test protocol version getters on the server when a supported versions extension is received */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        for (uint8_t client_hello_version = S2N_SSLv3; client_hello_version <= S2N_TLS13; client_hello_version++) {
            for (uint8_t client_supported_version = S2N_SSLv3; client_supported_version <= S2N_TLS13; client_supported_version++) {
                DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

                if (server_version == S2N_TLS12) {
                    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
                } else {
                    if (!s2n_is_tls13_fully_supported()) {
                        continue;
                    }
                    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
                }

                uint8_t supported_versions_data[3] = { 0 };
                struct s2n_blob supported_versions_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&supported_versions_blob, supported_versions_data, sizeof(supported_versions_data)));
                EXPECT_OK(s2n_write_test_supported_versions_extension(&supported_versions_blob, client_supported_version));

                /* The override_supported_versions client hello callback is used to overwrite the
                 * supported versions extension before the extension is processed.
                 */
                struct s2n_override_extension_ctx context = {
                    .extension_blob = supported_versions_blob
                };
                EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_override_supported_versions_cb, &context));

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client);
                EXPECT_SUCCESS(s2n_connection_set_config(client, config));

                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server);
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));

                EXPECT_SUCCESS(s2n_client_hello_send(client));

                /* Overwrite the client hello version according to the test case. */
                struct s2n_stuffer *hello_stuffer = &client->handshake.io;
                EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
                EXPECT_OK(s2n_write_protocol_version(hello_stuffer, client_hello_version));
                EXPECT_SUCCESS(s2n_stuffer_write(&server->handshake.io, &hello_stuffer->blob));

                EXPECT_SUCCESS(s2n_client_hello_recv(server));
                EXPECT_EQUAL(context.invoked_count, 1);

                /* Ensure that a supported versions extension was received. */
                bool supported_versions_received = false;
                EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                        &supported_versions_received));
                EXPECT_TRUE(supported_versions_received);

                EXPECT_EQUAL(s2n_connection_get_server_protocol_version(server), server_version);

                /* The reported client protocol version should always match the version specified
                 * in the supported versions extension, even for TLS 1.2 servers which don't
                 * process the extension for version selection.
                 */
                EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), client_supported_version);

                /* Clients indicate support for TLS 1.3 in the supported versions extension, not
                 * the client hello version. A client hello version above TLS 1.2 is never reported.
                 */
                EXPECT_EQUAL(s2n_connection_get_client_hello_version(server), MIN(client_hello_version, S2N_TLS12));

                uint8_t actual_protocol_version = s2n_connection_get_actual_protocol_version(server);
                if (server_version == S2N_TLS12) {
                    /* For backwards compatibility, TLS 1.2 servers always use the client hello
                     * version to determine the client's maximum version, even if a supported
                     * versions extension was received.
                     */
                    EXPECT_EQUAL(actual_protocol_version, MIN(server_version, client_hello_version));
                } else {
                    /* TLS 1.3 servers always use the version in the supported versions extension,
                     * regardless of the client hello version.
                     */
                    EXPECT_EQUAL(actual_protocol_version, MIN(server_version, client_supported_version));
                }
            }
        }
    }

    /* Test protocol version getters on the server when a supported versions extension isn't received */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        for (uint8_t client_hello_version = S2N_SSLv3; client_hello_version <= S2N_TLS12; client_hello_version++) {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);

            /* A TLS 1.2 security policy is set to prevent the client from sending a supported
             * versions extension.
             */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls12"));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

            if (server_version == S2N_TLS12) {
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_tls12"));
            } else {
                if (!s2n_is_tls13_fully_supported()) {
                    continue;
                }
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
            }

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            EXPECT_SUCCESS(s2n_client_hello_send(client));

            /* Overwrite the client hello version according to the test case. */
            struct s2n_stuffer *hello_stuffer = &client->handshake.io;
            EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
            EXPECT_OK(s2n_write_protocol_version(hello_stuffer, client_hello_version));
            EXPECT_SUCCESS(s2n_stuffer_write(&server->handshake.io, &hello_stuffer->blob));

            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            /* Ensure that a supported versions extension wasn't received. */
            bool supported_versions_received = false;
            EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                    &supported_versions_received));
            EXPECT_FALSE(supported_versions_received);

            EXPECT_EQUAL(s2n_connection_get_server_protocol_version(server), server_version);
            EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), client_hello_version);
            EXPECT_EQUAL(s2n_connection_get_client_hello_version(server), client_hello_version);
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server), client_hello_version);
        }
    }

    /* Test protocol version getters on the client */
    for (uint8_t server_version = S2N_SSLv3; server_version <= S2N_TLS13; server_version++) {
        if (server_version == S2N_TLS13 && !s2n_is_tls13_fully_supported()) {
            continue;
        }

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        server->server_protocol_version = server_version;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server, &io_pair));

        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_CERT));

        EXPECT_EQUAL(s2n_connection_get_server_protocol_version(client), server_version);
        EXPECT_EQUAL(s2n_connection_get_client_protocol_version(client), s2n_get_highest_fully_supported_tls_version());
        EXPECT_EQUAL(s2n_connection_get_client_hello_version(client), S2N_TLS12);
        EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(client), server_version);
    }

    /* Ensure that TLS 1.2 servers report the client hello version as the client protocol version
     * if a malformed supported versions extension was received
     */
    for (uint8_t client_hello_version = S2N_SSLv3; client_hello_version <= S2N_TLS12; client_hello_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));

        uint8_t supported_versions_data[1] = { 0 };
        struct s2n_blob supported_versions_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&supported_versions_blob, supported_versions_data, sizeof(supported_versions_data)));
        EXPECT_OK(s2n_write_malformed_supported_versions_extension(&supported_versions_blob));

        struct s2n_override_extension_ctx context = {
            .extension_blob = supported_versions_blob
        };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_override_supported_versions_cb, &context));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_client_hello_send(client));

        /* Overwrite the client hello version according to the test case. */
        struct s2n_stuffer *hello_stuffer = &client->handshake.io;
        EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
        EXPECT_OK(s2n_write_protocol_version(hello_stuffer, client_hello_version));
        EXPECT_SUCCESS(s2n_stuffer_write(&server->handshake.io, &hello_stuffer->blob));

        EXPECT_SUCCESS(s2n_client_hello_recv(server));
        EXPECT_EQUAL(context.invoked_count, 1);

        /* Ensure that a supported versions extension was received. */
        bool supported_versions_received = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                &supported_versions_received));
        EXPECT_TRUE(supported_versions_received);

        EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), client_hello_version);
    }

    /* Ensure that TLS 1.2 servers report the client hello version as the client protocol version
     * if an invalid supported version is received
     */
    for (uint8_t client_hello_version = S2N_SSLv3; client_hello_version <= S2N_TLS12; client_hello_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));

        uint8_t invalid_supported_version = S2N_TLS13 + 10;

        uint8_t supported_versions_data[3] = { 0 };
        struct s2n_blob supported_versions_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&supported_versions_blob, supported_versions_data, sizeof(supported_versions_data)));
        EXPECT_OK(s2n_write_test_supported_versions_extension(&supported_versions_blob, invalid_supported_version));

        struct s2n_override_extension_ctx context = {
            .extension_blob = supported_versions_blob
        };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_override_supported_versions_cb, &context));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        struct s2n_stuffer *hello_stuffer = &client->handshake.io;
        EXPECT_SUCCESS(s2n_client_hello_send(client));

        /* Overwrite the client hello version according to the test case. */
        EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
        EXPECT_OK(s2n_write_protocol_version(hello_stuffer, client_hello_version));
        EXPECT_SUCCESS(s2n_stuffer_write(&server->handshake.io, &hello_stuffer->blob));

        EXPECT_SUCCESS(s2n_client_hello_recv(server));
        EXPECT_EQUAL(context.invoked_count, 1);

        /* Ensure that a supported versions extension was received. */
        bool supported_versions_received = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                &supported_versions_received));
        EXPECT_TRUE(supported_versions_received);

        EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), client_hello_version);
    }

    END_TEST();
}
