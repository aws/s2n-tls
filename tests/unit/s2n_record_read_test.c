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
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

#define SSLV2_MIN_SIZE 3

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Test s2n_sslv2_record_header_parse */
    {
        const struct {
            uint8_t bytes[S2N_TLS_RECORD_HEADER_LENGTH];
            uint16_t length;
            uint8_t type;
            uint8_t version;
        } test_cases[] = {
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE, TLS_CLIENT_HELLO, 0x03, 0x03 },
                    .length = 0,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE + 1, TLS_CLIENT_HELLO, 0x03, 0x03 },
                    .length = 1,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, 0xFF, TLS_CLIENT_HELLO, 0x03, 0x03 },
                    .length = 0xFF - SSLV2_MIN_SIZE,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, 0x84, TLS_CLIENT_HELLO, 0x03, 0x03 },
                    .length = 0x84 - SSLV2_MIN_SIZE,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { 0x84, 0x84, TLS_CLIENT_HELLO, 0x03, 0x03 },
                    .length = 0x484 - SSLV2_MIN_SIZE,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { 0xFF, 0xFF, TLS_CLIENT_HELLO, 0x03, 0x03 },
                    .length = 0x7FFF - SSLV2_MIN_SIZE,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE, 0, 0x03, 0x03 },
                    .length = 0,
                    .type = 0,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE, 77, 0x03, 0x03 },
                    .length = 0,
                    .type = 77,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE, TLS_SERVER_HELLO, 0x03, 0x03 },
                    .length = 0,
                    .type = TLS_SERVER_HELLO,
                    .version = S2N_TLS12,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE, TLS_CLIENT_HELLO, 0x03, 0x04 },
                    .length = 0,
                    .type = TLS_CLIENT_HELLO,
                    .version = S2N_TLS13,
            },
            {
                    .bytes = { S2N_TLS_SSLV2_HEADER_FLAG, SSLV2_MIN_SIZE, TLS_CLIENT_HELLO, 0, 0 },
                    .length = 0,
                    .type = TLS_CLIENT_HELLO,
                    .version = 0,
            },
        };

        /* Test: parse valid record headers */
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->header_in,
                    test_cases[i].bytes, sizeof(test_cases[i].bytes)));

            uint8_t type = 0, version = 0;
            uint16_t length = 0;
            EXPECT_SUCCESS(s2n_sslv2_record_header_parse(conn, &type, &version, &length));
            EXPECT_EQUAL(test_cases[i].type, type);
            EXPECT_EQUAL(test_cases[i].version, version);
            EXPECT_EQUAL(test_cases[i].length, length);

            EXPECT_BYTEARRAY_EQUAL(conn->header_in_data,
                    test_cases[i].bytes, sizeof(test_cases[i].bytes));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->header_in), S2N_TLS_RECORD_HEADER_LENGTH);
        }

        /* Test: parse header with bad length
         *
         * We already read 3 bytes by reading the header, so logically the message
         * is at least 3 bytes long.
         */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH));
            conn->header_in_data[0] = S2N_TLS_SSLV2_HEADER_FLAG;

            uint8_t type = 0, version = 0;
            uint16_t length = 0;

            conn->header_in_data[1] = SSLV2_MIN_SIZE - 1;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_sslv2_record_header_parse(conn, &type, &version, &length),
                    S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->header_in), 3);
            EXPECT_SUCCESS(s2n_stuffer_reread(&conn->header_in));

            conn->header_in_data[1] = SSLV2_MIN_SIZE;
            EXPECT_SUCCESS(s2n_sslv2_record_header_parse(conn, &type, &version, &length));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->header_in), S2N_TLS_RECORD_HEADER_LENGTH);
            EXPECT_SUCCESS(s2n_stuffer_reread(&conn->header_in));

            conn->header_in_data[1] = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_sslv2_record_header_parse(conn, &type, &version, &length),
                    S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->header_in), 3);
            EXPECT_SUCCESS(s2n_stuffer_reread(&conn->header_in));
        };
    };

    END_TEST();
}
