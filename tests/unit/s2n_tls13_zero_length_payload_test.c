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
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_record.h"
#include "tls/s2n_handshake_io.c"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#include <stdint.h>
#include <stdlib.h>
#include <s2n.h>
#include <fcntl.h>
#include <sys/wait.h>

/* In TLS 1.3, encrypted handshake records would appear to be of record type TLS_APPLICATION_DATA.
*  The actual record content type is found after
*/
const char tls13_zero_length_application_record_hex[] = "170303000117";
const char tls13_zero_length_handshake_record_hex[] = "1603030000";
const char tls13_zero_length_alert_record_hex[] = "1503030000";


int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test 0 length application data record handled gracefully in client and server mode */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        DEFER_CLEANUP(struct s2n_stuffer client_to_server = {0}, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_to_client = {0}, s2n_stuffer_free);

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));

        S2N_BLOB_FROM_HEX(record_header_blob, tls13_zero_length_application_record_hex);
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&client_to_server, record_header_blob.data, record_header_blob.size));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_to_client, record_header_blob.data, record_header_blob.size));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_to_server), S2N_TLS_RECORD_HEADER_LENGTH + 1);
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_to_client), S2N_TLS_RECORD_HEADER_LENGTH + 1);

        uint8_t record_type;
        int isSSLv2;

        EXPECT_SUCCESS(s2n_read_full_record(server_conn, &record_type, &isSSLv2));
        EXPECT_EQUAL(record_type, TLS_APPLICATION_DATA);
        record_type = 0;
        EXPECT_SUCCESS(s2n_read_full_record(client_conn, &record_type, &isSSLv2));
        EXPECT_EQUAL(record_type, TLS_APPLICATION_DATA);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test 0 length payload in handshake record terminates connection in client and server mode */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        DEFER_CLEANUP(struct s2n_stuffer client_to_server = {0}, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_to_client = {0}, s2n_stuffer_free);

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));

        S2N_BLOB_FROM_HEX(record_header_blob, tls13_zero_length_handshake_record_hex);
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&client_to_server, record_header_blob.data, record_header_blob.size));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_to_client, record_header_blob.data, record_header_blob.size));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_to_server), S2N_TLS_RECORD_HEADER_LENGTH);
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_to_client), S2N_TLS_RECORD_HEADER_LENGTH);

        EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(server_conn), S2N_ERR_BAD_MESSAGE);
        EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test 0 length payload in alert record terminates connection in client and server modes */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        DEFER_CLEANUP(struct s2n_stuffer client_to_server = {0}, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_to_client = {0}, s2n_stuffer_free);

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));

        S2N_BLOB_FROM_HEX(record_header_blob, tls13_zero_length_alert_record_hex);
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&client_to_server, record_header_blob.data, record_header_blob.size));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_to_client, record_header_blob.data, record_header_blob.size));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_to_server), S2N_TLS_RECORD_HEADER_LENGTH);
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_to_client), S2N_TLS_RECORD_HEADER_LENGTH);

        EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(server_conn), S2N_ERR_BAD_MESSAGE);
        EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    END_TEST();

    return 0;
}
