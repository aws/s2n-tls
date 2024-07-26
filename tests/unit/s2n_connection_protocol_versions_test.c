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

static S2N_RESULT s2n_write_test_supported_versions_extension(struct s2n_blob *supported_versions_blob, uint8_t version,
        uint8_t extension_length)
{
    RESULT_ENSURE_REF(supported_versions_blob);

    struct s2n_stuffer supported_versions_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&supported_versions_stuffer, supported_versions_blob));

    /* Write the length byte. */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, extension_length));
    /* Write the supported version. */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, version / 10));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&supported_versions_stuffer, version % 10));

    return S2N_RESULT_OK;
}

struct s2n_overwrite_client_hello_ctx {
    uint8_t client_hello_version;
    uint8_t client_supported_version;
    uint8_t extension_length;

    uint8_t supported_versions_data[3];
    int invoked_count;
};

static int s2n_overwrite_client_hello_cb(struct s2n_connection *conn, void *ctx)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(ctx);

    struct s2n_overwrite_client_hello_ctx *context = (struct s2n_overwrite_client_hello_ctx *) ctx;
    context->invoked_count += 1;

    if (context->extension_length) {
        struct s2n_blob supported_versions_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&supported_versions_blob, context->supported_versions_data,
                sizeof(context->supported_versions_data)));

        struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
        EXPECT_NOT_NULL(client_hello);

        s2n_extension_type_id supported_versions_id = 0;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(S2N_EXTENSION_SUPPORTED_VERSIONS, &supported_versions_id));
        s2n_parsed_extension *extension = &client_hello->extensions.parsed_extensions[supported_versions_id];

        EXPECT_OK(s2n_write_test_supported_versions_extension(&supported_versions_blob,
                context->client_supported_version, context->extension_length));

        extension->extension_type = S2N_EXTENSION_SUPPORTED_VERSIONS;
        extension->extension = supported_versions_blob;
    }

    /* The client version fields are set when parsing the client hello before the client hello
     * callback is invoked. The version fields are overridden to emulate receiving a client hello
     * with a different version.
     */
    if (context->client_hello_version) {
        conn->client_hello_version = context->client_hello_version;
        conn->client_protocol_version = context->client_hello_version;
    }

    return S2N_SUCCESS;
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
        for (uint8_t client_hello_version = S2N_SSLv3; client_hello_version <= S2N_TLS12; client_hello_version++) {
            for (uint8_t client_supported_version = S2N_SSLv3; client_supported_version <= S2N_TLS13; client_supported_version++) {
                DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

                if (server_version == S2N_TLS12) {
                    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
                } else if (s2n_is_tls13_fully_supported()) {
                    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
                } else {
                    continue;
                }

                struct s2n_overwrite_client_hello_ctx context = {
                    .client_hello_version = client_hello_version,
                    .client_supported_version = client_supported_version,
                    .extension_length = 2,
                };
                EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_overwrite_client_hello_cb, &context));

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client);
                EXPECT_SUCCESS(s2n_connection_set_config(client, config));

                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server);
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));

                DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));
                EXPECT_EQUAL(context.invoked_count, 1);

                /* Ensure that a supported versions extension was received. */
                bool supported_versions_received = false;
                EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                        &supported_versions_received));
                EXPECT_TRUE(supported_versions_received);

                EXPECT_EQUAL(s2n_connection_get_server_protocol_version(server), server_version);
                EXPECT_EQUAL(s2n_connection_get_client_hello_version(server), client_hello_version);

                /* The reported client protocol version should always match the version specified
                 * in the supported versions extension, even for TLS 1.2 servers which don't
                 * process the extension for version selection.
                 */
                EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), client_supported_version);

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
            } else if (s2n_is_tls13_fully_supported()) {
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
            } else {
                continue;
            }

            struct s2n_overwrite_client_hello_ctx context = {
                .client_hello_version = client_hello_version,
            };
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, s2n_overwrite_client_hello_cb, &context));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));
            EXPECT_EQUAL(context.invoked_count, 1);

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
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

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

        struct s2n_overwrite_client_hello_ctx context = {
            .client_hello_version = client_hello_version,
            .client_supported_version = S2N_TLS13,
            /* Write an invalid length */
            .extension_length = 11,
        };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_overwrite_client_hello_cb, &context));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));
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

        struct s2n_overwrite_client_hello_ctx context = {
            .client_hello_version = client_hello_version,
            /* Write an invalid version */
            .client_supported_version = S2N_TLS13 + 10,
            .extension_length = 2,
        };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_overwrite_client_hello_cb, &context));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));
        EXPECT_EQUAL(context.invoked_count, 1);

        /* Ensure that a supported versions extension was received. */
        bool supported_versions_received = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                &supported_versions_received));
        EXPECT_TRUE(supported_versions_received);

        EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), client_hello_version);
    }

    /* Ensure that TLS 1.3 servers report an unknown protocol version if a supported versions
     * extension can't be processed
     */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));

        struct s2n_overwrite_client_hello_ctx context = {
            .client_supported_version = S2N_TLS13,
            /* Write an invalid length */
            .extension_length = 11,
        };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_overwrite_client_hello_cb, &context));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO),
                S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(context.invoked_count, 1);

        /* Ensure that a supported versions extension was received. */
        bool supported_versions_received = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(&server->client_hello, S2N_EXTENSION_SUPPORTED_VERSIONS,
                &supported_versions_received));
        EXPECT_TRUE(supported_versions_received);

        EXPECT_EQUAL(s2n_connection_get_server_protocol_version(server), S2N_TLS13);
        EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), s2n_unknown_protocol_version);
        EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server), s2n_unknown_protocol_version);
    }

    END_TEST();
}
