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

#include <stdint.h>

#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_client_supported_versions.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#define PROTOCOL_VERSION_ALERT 70
#define GREASED_SUPPORTED_VERSION_EXTENSION_VALUES 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA

int get_alert(struct s2n_connection *conn) {
    uint8_t error[2];
    GUARD(s2n_stuffer_read_bytes(&conn->reader_alert_out, error, 2));
    return error[1];
}

int write_test_supported_versions_list(struct s2n_stuffer *list, uint8_t *supported_versions, uint8_t length) {
    GUARD(s2n_stuffer_write_uint8(list, length * S2N_TLS_PROTOCOL_VERSION_LEN));

    for (int i = 0; i < length; i++) {
        GUARD(s2n_stuffer_write_uint8(list, supported_versions[i] / 10));
        GUARD(s2n_stuffer_write_uint8(list, supported_versions[i] % 10));
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    uint8_t latest_version = S2N_TLS13;

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Client produces a version list that the server can parse */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        int size_result = s2n_extensions_client_supported_versions_size(client_conn);
        EXPECT_NOT_EQUAL(size_result, -1);
        uint16_t expected_length = size_result - S2N_EXTENSION_TYPE_FIELD_LENGTH - S2N_EXTENSION_LENGTH_FIELD_LENGTH;

        struct s2n_stuffer extension;
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
    }

    /* Server selects highest supported version shared by client */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t unsupported_client_version = 255;
        uint8_t supported_version_list[] = { S2N_TLS11, S2N_TLS12, S2N_TLS13, unsupported_client_version };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, latest_version);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server selects highest supported version shared by client (when server uses TLS1.2)
     * but retains the client's requested version. */
    {
        EXPECT_SUCCESS(s2n_disable_tls13());
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t unsupported_client_version = 255;
        uint8_t supported_version_list[] = { S2N_TLS11, S2N_TLS12, S2N_TLS13, unsupported_client_version };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_SUCCESS(s2n_enable_tls13());
        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server terminates connection if there are no supported version in the list */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t invalid_version_list[] = { 0x0020, 0x0021, 0x0403, 0x0305, 0x7a7a, 0x0201 };
        uint8_t invalid_version_list_length = s2n_array_len(invalid_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        GUARD(s2n_stuffer_write_uint8(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (int i = 0; i < invalid_version_list_length; i++) {
            GUARD(s2n_stuffer_write_uint16(&extension, invalid_version_list[i]));
        }

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Check grease values for the supported versions */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t grease_version_list[] = { 0x0304, GREASED_SUPPORTED_VERSION_EXTENSION_VALUES };
        uint8_t grease_version_list_length = s2n_array_len(grease_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, grease_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        GUARD(s2n_stuffer_write_uint8(&extension, grease_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (int i = 0; i < grease_version_list_length; i++) {
            GUARD(s2n_stuffer_write_uint16(&extension, grease_version_list[i]));
        }

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server selects highest supported protocol among list of invalid protocols (that purposefully test our conversion methods) */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t invalid_version_list[] = { 0x0020, 0x0200, 0x0201, 0x0304, 0x0021, 0x0305, 0x0403, 0x7a7a };
        uint8_t invalid_version_list_length = s2n_array_len(invalid_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 1);

        GUARD(s2n_stuffer_write_uint8(&extension, invalid_version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN));

        for (int i = 0; i < invalid_version_list_length; i++) {
            GUARD(s2n_stuffer_write_uint16(&extension, invalid_version_list[i]));
        }

        EXPECT_SUCCESS(s2n_client_supported_versions_extension.recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->server_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server alerts if no shared supported version found */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t supported_version_list[] = { S2N_UNKNOWN_PROTOCOL_VERSION };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(get_alert(server_conn), PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server alerts if supported version list is empty */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(get_alert(server_conn), PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server alerts if version list size exceeds the extension size */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 13));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(get_alert(server_conn), PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server alerts if version list size is less than extension size */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, 5);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 2));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0302));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0303));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(get_alert(server_conn), PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Server alerts if version list size is odd */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, 4);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 3));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension, 0x0302));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x03));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_supported_versions_extension.recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(get_alert(server_conn), PROTOCOL_VERSION_ALERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

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
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
