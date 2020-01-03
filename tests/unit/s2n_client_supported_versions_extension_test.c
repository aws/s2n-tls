/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
        uint16_t expected_length = (uint16_t) size_result;

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, expected_length);

        EXPECT_SUCCESS(s2n_extensions_client_supported_versions_send(client_conn, &extension));

        /* Check that the type and size are correct */
        uint16_t extension_type;
        s2n_stuffer_read_uint16(&extension, &extension_type);
        EXPECT_EQUAL(extension_type, TLS_EXTENSION_SUPPORTED_VERSIONS);
        uint16_t extension_length;
        s2n_stuffer_read_uint16(&extension, &extension_length);
        EXPECT_EQUAL(extension_length, s2n_stuffer_data_available(&extension));

        /* Check that the server can process the version list */
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Server should negotiate the most recent version */
        EXPECT_SUCCESS(s2n_extensions_client_supported_versions_recv(server_conn, &extension));
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
        uint8_t supported_version_list[] = { S2N_TLS11, S2N_TLS12, unsupported_client_version };
        uint8_t supported_version_list_length = sizeof(supported_version_list);

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, supported_version_list_length * 2 + 1);

        EXPECT_SUCCESS(write_test_supported_versions_list(&extension, supported_version_list,
                supported_version_list_length));

        EXPECT_SUCCESS(s2n_extensions_client_supported_versions_recv(server_conn, &extension));
        EXPECT_EQUAL(server_conn->client_protocol_version, unsupported_client_version);
        EXPECT_EQUAL(server_conn->server_protocol_version, latest_version);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

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

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_supported_versions_recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
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

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_supported_versions_recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
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

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_supported_versions_recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
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

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_supported_versions_recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
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

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_supported_versions_recv(server_conn, &extension), S2N_ERR_BAD_MESSAGE);
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
