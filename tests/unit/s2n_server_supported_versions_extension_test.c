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

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_supported_versions.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int write_test_supported_version(struct s2n_stuffer *list, uint8_t supported_version) {
    GUARD(s2n_stuffer_write_uint8(list, S2N_TLS_PROTOCOL_VERSION_LEN));

    GUARD(s2n_stuffer_write_uint8(list, supported_version / 10));
    GUARD(s2n_stuffer_write_uint8(list, supported_version % 10));

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());
    uint8_t latest_version = S2N_TLS13;

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Server sends a supported_version the client can parse */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t expected_length = 6;

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, expected_length);

        EXPECT_SUCCESS(s2n_extensions_server_supported_versions_send(server_conn, &extension));

        /* Check that type and size are correct */
        uint16_t extension_type;
        s2n_stuffer_read_uint16(&extension, &extension_type);
        EXPECT_EQUAL(extension_type, TLS_EXTENSION_SUPPORTED_VERSIONS);
        uint16_t extension_length;
        s2n_stuffer_read_uint16(&extension, &extension_length);
        EXPECT_EQUAL(extension_length, s2n_stuffer_data_available(&extension));

        /* Check that the client can process the version */
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        EXPECT_SUCCESS(s2n_extensions_server_supported_versions_recv(client_conn, &extension));
        EXPECT_EQUAL(client_conn->client_protocol_version, latest_version);
        EXPECT_EQUAL(client_conn->server_protocol_version, latest_version);
        EXPECT_EQUAL(client_conn->actual_protocol_version, latest_version);

        /* Clean up */
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Client alerts if supported_version less than min supported by client */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        uint8_t unsupported_version_unknown = S2N_UNKNOWN_PROTOCOL_VERSION;

        uint16_t supported_version_length = 6;

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, supported_version_length);

        EXPECT_SUCCESS(write_test_supported_version(&extension, unsupported_version_unknown));
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_supported_versions_recv(client_conn, &extension), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Client alerts if supported_version greater than max supported by client */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        uint8_t unsupported_version_gt_tls13 = 255;

        uint16_t supported_version_length = 6;

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, supported_version_length);

        EXPECT_SUCCESS(write_test_supported_version(&extension, unsupported_version_gt_tls13));
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_supported_versions_recv(client_conn, &extension), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Client alerts if supported_version is empty */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, 1);
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_supported_versions_recv(client_conn, &extension), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    /* Client alerts if supported_version is malformed */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, 1);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 13));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_supported_versions_recv(client_conn, &extension), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
