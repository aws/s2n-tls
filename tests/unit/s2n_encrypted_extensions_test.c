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

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_supported_versions.h"

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());
    uint8_t latest_version = S2N_TLS13;

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Server successfully sends empty encrypted extension */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t encrypted_extensions_expected_size = 2;
        uint16_t encrypted_extensions_expected_length = 0;

        EXPECT_SUCCESS(s2n_encrypted_extensions_send(server_conn));

        /* Check that size and data in server_conn->handshake.io are correct */
        struct s2n_stuffer *server_out = &server_conn->handshake.io;
        uint16_t encrypted_extensions_actual_length;

        EXPECT_EQUAL(encrypted_extensions_expected_size, s2n_stuffer_data_available(server_out));
        s2n_stuffer_read_uint16(server_out, &encrypted_extensions_actual_length);
        EXPECT_EQUAL(encrypted_extensions_expected_length, encrypted_extensions_actual_length);
        EXPECT_EQUAL(encrypted_extensions_actual_length, s2n_stuffer_data_available(server_out));

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(server_out));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Client successfully receives empty encrypted extension */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        EXPECT_SUCCESS(s2n_encrypted_extensions_send(client_conn));
        EXPECT_SUCCESS(s2n_encrypted_extensions_recv(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Client successefully parses a non-empty encrypted extension */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        /* Write length of ALPN extension, then write the extension itself */
        strcpy(client_conn->application_protocol, "h2");
        const uint8_t application_protocol_len = strlen(client_conn->application_protocol);
        uint16_t alpn_extension_length = 7 + application_protocol_len;
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, alpn_extension_length));

        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, TLS_EXTENSION_ALPN));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, application_protocol_len + 3));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, application_protocol_len + 1));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, application_protocol_len));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&client_conn->handshake.io, (uint8_t *) client_conn->application_protocol, application_protocol_len));

        /* Client parses encrypted extensions */
        strcpy(client_conn->application_protocol, "");
        EXPECT_SUCCESS(s2n_encrypted_extensions_recv(client_conn));
        EXPECT_SUCCESS(strcmp(client_conn->application_protocol, "h2"));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Client does not parse a non-EE extension */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        client_conn->server_protocol_version = latest_version;

        /* write length of supported versions extension (6) then write the extension itself */
        uint16_t supported_versions_extension_length = 6;
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, supported_versions_extension_length));
        EXPECT_SUCCESS(s2n_extensions_server_supported_versions_send(client_conn, &client_conn->handshake.io));

        client_conn->server_protocol_version = 0;
        EXPECT_FAILURE_WITH_ERRNO(s2n_encrypted_extensions_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(client_conn->client_protocol_version, latest_version);
        EXPECT_NOT_EQUAL(client_conn->server_protocol_version, latest_version);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
