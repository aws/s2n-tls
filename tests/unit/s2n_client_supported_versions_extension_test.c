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

int write_test_supported_versions_list(struct s2n_stuffer *list, uint8_t *supported_versions, uint8_t length)
{
    POSIX_GUARD(s2n_stuffer_write_uint8(list, length * S2N_TLS_PROTOCOL_VERSION_LEN));

    for (size_t i = 0; i < length; i++) {
        POSIX_GUARD(s2n_stuffer_write_uint8(list, supported_versions[i] / 10));
        POSIX_GUARD(s2n_stuffer_write_uint8(list, supported_versions[i] % 10));
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    uint8_t latest_version = S2N_TLS13;

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    const struct s2n_security_policy *security_policy_with_tls13_and_earlier = &security_policy_20190801;
    EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy_with_tls13_and_earlier));
    EXPECT_EQUAL(security_policy_with_tls13_and_earlier->minimum_protocol_version, S2N_TLS10);

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
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t unsupported_client_version = 255;
        uint8_t supported_version_list[] = { S2N_TLS11, S2N_TLS12, S2N_TLS13, unsupported_client_version };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, latest_version);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server does not process the extension if using TLS1.2. */
    {
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t unsupported_client_version = 255;
        uint8_t supported_version_list[] = { S2N_TLS11, S2N_TLS12, S2N_TLS13, unsupported_client_version };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);
        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server terminates connection if there are no supported version in the list */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t invalid_version_list[] = { 0x0020, 0x0021, 0x0403, 0x0305, 0x7a7a, 0x0201 };
        uint8_t invalid_version_list_length = s2n_array_len(invalid_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        POSIX_GUARD(s2n_stuffer_write_uint8(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (size_t i = 0; i < invalid_version_list_length; i++) {
            POSIX_GUARD(s2n_stuffer_write_uint16(&extension, invalid_version_list[i]));
        }

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension),
                S2N_ERR_UNKNOWN_PROTOCOL_VERSION);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Check grease values for the supported versions */
    {
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
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t invalid_version_list[] = { 0x0020, 0x0200, 0x0201, 0x0304, 0x0021, 0x0305, 0x0403, 0x7a7a };
        uint8_t invalid_version_list_length = s2n_array_len(invalid_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        POSIX_GUARD(s2n_stuffer_write_uint8(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (size_t i = 0; i < invalid_version_list_length; i++) {
            POSIX_GUARD(s2n_stuffer_write_uint16(&extension, invalid_version_list[i]));
        }

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if no shared supported version found */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t supported_version_list[] = { S2N_SSLv3 };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension),
                S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
        EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if supported version list is empty */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension),
                S2N_ERR_UNKNOWN_PROTOCOL_VERSION);
        EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if version list size exceeds the extension size */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 13));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if version list size is less than extension size */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 5);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 2));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0302));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0303));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    };

    /* Server alerts if version list size is odd */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension = { 0 };
        s2n_stuffer_alloc(&extension, 4);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 3));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0302));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x03));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(server_conn->reader_alert_out, PROTOCOL_VERSION_ALERT);

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
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config_with_cert = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_cert, chain_and_key));

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

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
