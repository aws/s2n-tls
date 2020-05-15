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

#include "tls/extensions/s2n_client_ec_point_format.h"
#include "tls/s2n_resume.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_ec_point_format_extension.send(conn, &stuffer));

        uint8_t length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &length));
        EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));

        uint8_t point_format;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &point_format));
        EXPECT_EQUAL(point_format, TLS_EC_POINT_FORMAT_UNCOMPRESSED);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_ec_point_format_extension.send(conn, &stuffer));

        EXPECT_FALSE(conn->ec_point_formats);
        EXPECT_SUCCESS(s2n_client_ec_point_format_extension.recv(conn, &stuffer));
        EXPECT_TRUE(conn->ec_point_formats);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
