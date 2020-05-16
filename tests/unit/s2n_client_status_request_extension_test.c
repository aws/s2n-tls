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

#include "tls/extensions/s2n_client_status_request.h"
#include "tls/s2n_resume.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Test should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* status request should NOT be sent by default */
        EXPECT_FALSE(s2n_client_status_request_extension.should_send(conn));

        /* status request should be sent if ocsp requested */
        config->status_request_type = S2N_STATUS_REQUEST_OCSP;
        EXPECT_TRUE(s2n_client_status_request_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Enable status requests */
    config->status_request_type = S2N_STATUS_REQUEST_OCSP;

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_status_request_extension.send(conn, &stuffer));

        uint8_t request_type;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &request_type));
        EXPECT_EQUAL(request_type, S2N_STATUS_REQUEST_OCSP);

        uint32_t unused_values;
        EXPECT_SUCCESS(s2n_stuffer_read_uint32(&stuffer, &unused_values));
        EXPECT_EQUAL(unused_values, 0);

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

        EXPECT_SUCCESS(s2n_client_status_request_extension.send(conn, &stuffer));

        EXPECT_EQUAL(conn->status_type, S2N_STATUS_REQUEST_NONE);
        EXPECT_SUCCESS(s2n_client_status_request_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->status_type, S2N_STATUS_REQUEST_OCSP);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test recv - malformed length, ignore */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_status_request_extension.send(conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, sizeof(uint16_t)));

        EXPECT_EQUAL(conn->status_type, S2N_STATUS_REQUEST_NONE);
        EXPECT_SUCCESS(s2n_client_status_request_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->status_type, S2N_STATUS_REQUEST_NONE);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test recv - not ocsp request, ignore */
    {
        struct s2n_config *bad_config;
        EXPECT_NOT_NULL(bad_config = s2n_config_new());
        bad_config->status_request_type = UINT8_MAX;

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, bad_config));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_status_request_extension.send(conn, &stuffer));

        EXPECT_EQUAL(conn->status_type, S2N_STATUS_REQUEST_NONE);
        EXPECT_SUCCESS(s2n_client_status_request_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->status_type, S2N_STATUS_REQUEST_NONE);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(bad_config));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
