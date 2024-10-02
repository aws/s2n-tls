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

#include "testlib/s2n_testlib.h"

#include "s2n_test.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test that s2n_negotiate_test_server_and_client produces useful errors.
     * In the past, we failed to surface errors and instead reported io errors when
     * the failed connection's peer couldn't read the next expected message.
     *
     * We should always report the actual error to allow better debugging of tests.
     */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
        POSIX_GUARD(s2n_io_pair_init_non_blocking(&io_pair));
        POSIX_GUARD(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* This should NEVER fail with an error related to blocked IO. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, NULL), S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test s2n_blob_alloc_from_hex_with_whitespace */
    {
        struct {
            const char *input;
            size_t expected_output_size;
            uint8_t expected_output[100];
        } test_cases[] = {
            { .input = "abcd", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "ab cd", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = " abcd", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "abcd ", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "  ab     cd  ", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "", .expected_output = { 0 }, .expected_output_size = 0 },
            { .input = " ", .expected_output = { 0 }, .expected_output_size = 0 },
            { .input = "12 34 56 78 90", .expected_output = { 18, 52, 86, 120, 144 }, .expected_output_size = 5 },
            { .input = "1234567890", .expected_output = { 18, 52, 86, 120, 144 }, .expected_output_size = 5 },
        };
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_blob actual_output = { 0 }, s2n_free);
            EXPECT_OK(s2n_blob_alloc_from_hex_with_whitespace(&actual_output, test_cases[i].input));
            EXPECT_EQUAL(actual_output.size, test_cases[i].expected_output_size);
            EXPECT_BYTEARRAY_EQUAL(actual_output.data, test_cases[i].expected_output, actual_output.size);
        }
    };

    END_TEST();
}
