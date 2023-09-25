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

#include <stdint.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_supported_versions.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

#define PROTOCOL_VERSION_ALERT                     70
#define GREASED_SUPPORTED_VERSION_EXTENSION_VALUES 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA

#define S2N_TEST_MAX_SUPPORTED_VERSIONS            10
#define S2N_TEST_SUPPORTED_VERSIONS_EXTENSION_SIZE (1 + (S2N_TEST_MAX_SUPPORTED_VERSIONS * 2))

int write_test_supported_versions_list(struct s2n_stuffer *list, uint8_t *supported_versions, uint8_t length)
{
    POSIX_GUARD(s2n_stuffer_write_uint8(list, length * S2N_TLS_PROTOCOL_VERSION_LEN));

    for (size_t i = 0; i < length; i++) {
        POSIX_GUARD(s2n_stuffer_write_uint8(list, supported_versions[i] / 10));
        POSIX_GUARD(s2n_stuffer_write_uint8(list, supported_versions[i] % 10));
    }

    return 0;
}

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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t latest_version = S2N_TLS13;

    const struct s2n_security_policy *security_policy_with_tls13_and_earlier = &security_policy_20190801;
    EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy_with_tls13_and_earlier));
    EXPECT_EQUAL(security_policy_with_tls13_and_earlier->minimum_protocol_version, S2N_TLS10);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    const uint8_t unknown_client_version = 255;

    /* Client offers all supported versions in version list */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->security_policy_override = security_policy_with_tls13_and_earlier;

        struct s2n_stuffer extension = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
        EXPECT_SUCCESS(s2n_client_supported_versions_extension.send(conn, &extension));

        /* Total supported versions.
         * If the "+1" looks wrong, consider what would happen if latest_version == S2N_TLS10. */
        size_t supported_versions = (latest_version - S2N_TLS10) + 1;

        /* Check extension contains enough versions */
        uint8_t version_list_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&extension, &version_list_size));
        EXPECT_EQUAL(version_list_size, S2N_TLS_PROTOCOL_VERSION_LEN * supported_versions);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Client doesn't offer <TLS1.3 in the version list if QUIC enabled */
    if (s2n_is_tls13_fully_supported()) {
        /* For simplicity, we assume TLS1.3 is the latest version. */
        EXPECT_EQUAL(latest_version, S2N_TLS13);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_enable_quic(conn));
        conn->security_policy_override = security_policy_with_tls13_and_earlier;

        struct s2n_stuffer extension = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
        EXPECT_SUCCESS(s2n_client_supported_versions_extension.send(conn, &extension));

        /* Check extension contains only one version */
        uint8_t version_list_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&extension, &version_list_size));
        EXPECT_EQUAL(version_list_size, S2N_TLS_PROTOCOL_VERSION_LEN);

        /* Check single version is TLS1.3 */
        uint16_t version = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&extension, &version));
        EXPECT_EQUAL(version, 0x0304);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Client produces a version list that the server can parse */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        int size_result = s2n_extensions_client_supported_versions_size(client_conn);
        EXPECT_NOT_EQUAL(size_result, -1);
        uint16_t expected_length = size_result - S2N_EXTENSION_TYPE_FIELD_LENGTH - S2N_EXTENSION_LENGTH_FIELD_LENGTH;

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, expected_length);

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.send(client_conn, &extension));

        /* Check that the size is correct */
        EXPECT_EQUAL(expected_length, s2n_stuffer_data_available(&extension));

        /* Check that the server can process the version list */
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Server should negotiate the most recent version */
        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, latest_version);
        EXPECT_EQUAL(server_conn->server_protocol_version, latest_version);
        EXPECT_EQUAL(server_conn->actual_protocol_version, latest_version);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server selects highest supported version shared by client */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        uint8_t supported_version_list[] = { S2N_TLS11, S2N_TLS12, S2N_TLS13, unknown_client_version };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, server_version);
        EXPECT_EQUAL(server_conn->actual_protocol_version, server_version);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server terminates connection if there are no supported version in the list */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        uint16_t invalid_version_list[] = { 0x0020, 0x0021, 0x0403, 0x0305, 0x7a7a, 0x0201 };
        uint8_t invalid_version_list_length = s2n_array_len(invalid_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        POSIX_GUARD(s2n_stuffer_write_uint8(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (size_t i = 0; i < invalid_version_list_length; i++) {
            POSIX_GUARD(s2n_stuffer_write_uint16(&extension, invalid_version_list[i]));
        }

        int ret = s2n_client_supported_versions_extension.recv(server_conn, &extension);
        if (server_version == S2N_TLS13) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_UNKNOWN_PROTOCOL_VERSION);
            EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);
        } else {
            /* TLS 1.2 servers should ignore the supported versions extension if a compatible
             * version can't be determined.
             */
            EXPECT_SUCCESS(ret);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Check grease values for the supported versions */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t grease_version_list[] = { 0x0304, GREASED_SUPPORTED_VERSION_EXTENSION_VALUES };
        uint8_t grease_version_list_length = s2n_array_len(grease_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, grease_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        POSIX_GUARD(s2n_stuffer_write_uint8(&extension, grease_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (size_t i = 0; i < grease_version_list_length; i++) {
            POSIX_GUARD(s2n_stuffer_write_uint16(&extension, grease_version_list[i]));
        }

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server selects highest supported protocol among list of invalid protocols (that purposefully test our conversion methods) */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        uint16_t invalid_version_list[] = { 0x0020, 0x0200, 0x0201, 0x0303, 0x0304, 0x0021, 0x0305, 0x0403, 0x7a7a };
        uint8_t invalid_version_list_length = s2n_array_len(invalid_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        POSIX_GUARD(s2n_stuffer_write_uint8(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (size_t i = 0; i < invalid_version_list_length; i++) {
            POSIX_GUARD(s2n_stuffer_write_uint16(&extension, invalid_version_list[i]));
        }

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, server_version);
        EXPECT_EQUAL(server_conn->actual_protocol_version, server_version);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if no shared supported version found */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        uint8_t supported_version_list[] = { S2N_SSLv3 };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        int ret = s2n_client_supported_versions_extension.recv(server_conn, &extension);
        if (server_version == S2N_TLS13) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
            EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);
        } else {
            /* TLS 1.2 servers should ignore the supported versions extension if a compatible
             * version can't be determined.
             */
            EXPECT_SUCCESS(ret);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if supported version list is empty */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        int ret = s2n_client_supported_versions_extension.recv(server_conn, &extension);

        if (server_version == S2N_TLS13) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_UNKNOWN_PROTOCOL_VERSION);
            EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);
        } else {
            /* TLS 1.2 servers should ignore the supported versions extension if a compatible
             * version can't be determined.
             */
            EXPECT_SUCCESS(ret);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if version list size exceeds the extension size */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 13));

        int ret = s2n_client_supported_versions_extension.recv(server_conn, &extension);
        if (server_version == S2N_TLS13) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);
        } else {
            /* TLS 1.2 servers should ignore a supported versions extension that's invalid. */
            EXPECT_SUCCESS(ret);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if version list size is less than extension size */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 5);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 2));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0302));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0303));

        int ret = s2n_client_supported_versions_extension.recv(server_conn, &extension);

        if (server_version == S2N_TLS13) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);
        } else {
            /* TLS 1.2 servers should ignore a supported versions extension that's invalid. */
            EXPECT_SUCCESS(ret);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if version list size is odd */
    for (uint8_t server_version = S2N_TLS12; server_version <= S2N_TLS13; server_version++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->server_protocol_version = server_version;

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 4);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 3));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0302));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x03));

        int ret = s2n_client_supported_versions_extension.recv(server_conn, &extension);

        if (server_version == S2N_TLS13) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);
        } else {
            /* TLS 1.2 servers should ignore a supported versions extension that's invalid. */
            EXPECT_SUCCESS(ret);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Since the supported_version extension replaces the version field
     * in the client hello, for backwards compatibility the version field
     * should be set to 1.2 even when a higher version is supported. */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_client_hello_send(conn));

        struct s2n_stuffer client_hello = conn->handshake.io;
        uint8_t version[2];
        s2n_stuffer_read_bytes(&client_hello, version, 2);

        EXPECT_EQUAL(version[0], 0x03);
        EXPECT_EQUAL(version[1], 0x03);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#appendix-D.2
     *= type=test
     *# A TLS server can also receive a ClientHello indicating a version number smaller than its highest supported
     *# version. If the "supported_versions" extension is present, the server MUST negotiate using that extension as
     *# described in Section 4.2.1.
     */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_config *config_with_cert = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_cert, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_cert, "default_tls13"));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_cert));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_cert));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        struct s2n_stuffer *hello_stuffer = NULL;
        hello_stuffer = &client_conn->handshake.io;
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        /* Overwrite the Client Hello protocol version to TLS10 */
        uint8_t small_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = { 0 };
        small_protocol_version[0] = S2N_TLS10 / 10;
        small_protocol_version[1] = S2N_TLS10 % 10;

        EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(hello_stuffer, small_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &hello_stuffer->blob));

        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* The server does not use the protocol version in the Client Hello to set the actual protocol version. */
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->client_hello_version, S2N_TLS10);
    }

    /* Test protocol version selection with the supported versions extension. */
    {
        struct test_case {
            uint8_t server_version;
            uint8_t client_hello_version;
            uint8_t client_supported_versions[S2N_TEST_MAX_SUPPORTED_VERSIONS];
            uint8_t expected_client_protocol_version;
            uint8_t expected_actual_protocol_version;
            s2n_error expected_error;
        } test_cases[] = {
            /* Receive a standard TLS 1.3 client hello. */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS12, S2N_TLS13 },
                    /* Ensure that a TLS 1.2 server correctly reports a client protocol version of
                     * TLS 1.3.
                     */
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS12, S2N_TLS13 },
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS13,
            },

            /* Receive a client hello with a TLS version higher than 1.3. */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS12, S2N_TLS13, 35 },
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS12, S2N_TLS13, 35 },
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS13,
            },

            /* Receive an empty supported versions list. */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { 0 },
                    .expected_client_protocol_version = S2N_TLS12,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { 0 },
                    .expected_error = S2N_ERR_UNKNOWN_PROTOCOL_VERSION,
            },

            /* Receive an unknown supported version. */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { unknown_client_version },
                    .expected_client_protocol_version = S2N_TLS12,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { unknown_client_version },
                    .expected_error = S2N_ERR_UNKNOWN_PROTOCOL_VERSION,
            },

            /* Receive a supported version that's not supported by the security policy. */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_SSLv3 },
                    .expected_client_protocol_version = S2N_TLS12,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_SSLv3 },
                    .expected_error = S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED,
            },

            /* Receive a supported version and a client hello version that aren't supported by the
             * security policy.
             */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_SSLv3,
                    .client_supported_versions = { S2N_SSLv3 },
                    .expected_error = S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_SSLv3,
                    .client_supported_versions = { S2N_SSLv3 },
                    .expected_error = S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED,
            },

            /* Ensure that the supported versions extension is used to select a protocol version,
             * even if the client hello version is less than TLS 1.2.
             */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS10,
                    .client_supported_versions = { S2N_TLS12, S2N_TLS13 },
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS10,
                    .client_supported_versions = { S2N_TLS12, S2N_TLS13 },
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS13,
            },

            /* Ensure that the supported versions extension is used to select a protocol version,
             * even if this version is less than the client hello version.
             */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS10 },
                    .expected_client_protocol_version = S2N_TLS10,
                    .expected_actual_protocol_version = S2N_TLS10,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS10 },
                    .expected_client_protocol_version = S2N_TLS10,
                    .expected_actual_protocol_version = S2N_TLS10,
            },

            /* Receive a client hello that only supports TLS 1.3. */
            {
                    .server_version = S2N_TLS12,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS13 },
                    /* A TLS 1.2 server will fail to process the supported versions extension due
                     * to not finding a compatible version, and will fall back to using the client
                     * hello version for protocol version selection. This will prevent the server
                     * from knowing the true client protocol version of TLS 1.3.
                     */
                    .expected_client_protocol_version = S2N_TLS12,
                    .expected_actual_protocol_version = S2N_TLS12,
            },
            {
                    .server_version = S2N_TLS13,
                    .client_hello_version = S2N_TLS12,
                    .client_supported_versions = { S2N_TLS13 },
                    .expected_client_protocol_version = S2N_TLS13,
                    .expected_actual_protocol_version = S2N_TLS13,
            },
        };

        for (int test_index = 0; test_index < s2n_array_len(test_cases); test_index++) {
            struct test_case test = test_cases[test_index];

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            if (test.server_version == S2N_TLS12) {
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
            } else {
                if (!s2n_is_tls13_fully_supported()) {
                    continue;
                }
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
            }

            size_t supported_versions_list_len = 0;
            for (int i = 0; i < S2N_TEST_MAX_SUPPORTED_VERSIONS; i++) {
                if (test.client_supported_versions[i] == 0) {
                    break;
                }
                supported_versions_list_len += 1;
            }
            /* 1 length byte + space for each of the versions in the test case. */
            size_t supported_versions_extension_size = 1 + (supported_versions_list_len * 2);

            uint8_t supported_versions_data[S2N_TEST_SUPPORTED_VERSIONS_EXTENSION_SIZE] = { 0 };
            struct s2n_blob supported_versions_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&supported_versions_blob, supported_versions_data, supported_versions_extension_size));

            struct s2n_stuffer supported_versions_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&supported_versions_stuffer, &supported_versions_blob));
            EXPECT_SUCCESS(write_test_supported_versions_list(&supported_versions_stuffer, test.client_supported_versions,
                    supported_versions_list_len));

            /* The override_supported_versions client hello callback is used to set or replace the
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

            struct s2n_stuffer *hello_stuffer = &client->handshake.io;
            EXPECT_SUCCESS(s2n_client_hello_send(client));

            /* Overwrite the client hello version according to the test case. */
            uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = { 0 };
            protocol_version[0] = test.client_hello_version / 10;
            protocol_version[1] = test.client_hello_version % 10;

            EXPECT_SUCCESS(s2n_stuffer_rewrite(hello_stuffer));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(hello_stuffer, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
            EXPECT_SUCCESS(s2n_stuffer_write(&server->handshake.io, &hello_stuffer->blob));

            int ret = s2n_client_hello_recv(server);

            if (test.expected_error) {
                EXPECT_FAILURE_WITH_ERRNO(ret, test.expected_error);
            } else {
                EXPECT_SUCCESS(ret);

                EXPECT_EQUAL(s2n_connection_get_server_protocol_version(server), test.server_version);
                EXPECT_EQUAL(s2n_connection_get_client_hello_version(server), test.client_hello_version);
                EXPECT_EQUAL(s2n_connection_get_client_protocol_version(server), test.expected_client_protocol_version);
                EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server), test.expected_actual_protocol_version);
            }

            EXPECT_EQUAL(context.invoked_count, 1);
        }
    }

    END_TEST();
    return 0;
}
