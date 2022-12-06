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
#include "tls/extensions/s2n_early_data_indication.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_nst_early_data_indication_should_send */
    {
        /* Safety check */
        EXPECT_FALSE(s2n_nst_early_data_indication_extension.should_send(NULL));

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);

        /* Should not send if max_early_data_size not set */
        EXPECT_FALSE(s2n_nst_early_data_indication_extension.should_send(conn));

        /* Should not send if max_early_data_size set to 0 */
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, 0));
        EXPECT_FALSE(s2n_nst_early_data_indication_extension.should_send(conn));

        /* Should send if max_early_data_size set to non-zero */
        uint32_t server_max = 13;
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, server_max));
        EXPECT_TRUE(s2n_nst_early_data_indication_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_nst_early_data_indiction_send */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = S2N_TLS13;

        struct s2n_stuffer output = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

        const uint32_t expected_max_early_data_size = 13;
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, expected_max_early_data_size));

        /* Safety checks */
        EXPECT_FAILURE_WITH_ERRNO(s2n_nst_early_data_indication_extension.send(conn, NULL), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_nst_early_data_indication_extension.send(NULL, &output), S2N_ERR_NULL);

        uint32_t actual_max_early_data_size = 0;
        EXPECT_SUCCESS(s2n_nst_early_data_indication_extension.send(conn, &output));
        EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &actual_max_early_data_size));
        EXPECT_EQUAL(expected_max_early_data_size, actual_max_early_data_size);

        EXPECT_SUCCESS(s2n_stuffer_free(&output));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_nst_early_data_indiction_recv */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = S2N_TLS13;

        struct s2n_stuffer input = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

        /* Safety checks */
        EXPECT_FAILURE_WITH_ERRNO(s2n_nst_early_data_indication_extension.recv(conn, NULL), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_nst_early_data_indication_extension.recv(NULL, &input), S2N_ERR_NULL);

        const uint32_t expected_max_early_data_size = 13;
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, expected_max_early_data_size));
        EXPECT_SUCCESS(s2n_nst_early_data_indication_extension.send(conn, &input));

        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, 0));
        EXPECT_SUCCESS(s2n_nst_early_data_indication_extension.recv(conn, &input));
        EXPECT_EQUAL(conn->server_max_early_data_size, expected_max_early_data_size);

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}
