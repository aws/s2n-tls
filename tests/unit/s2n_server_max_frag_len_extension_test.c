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
#include "tls/extensions/s2n_server_max_fragment_length.h"
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test should_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Should not send by default */
        EXPECT_FALSE(s2n_server_max_fragment_length_extension.should_send(conn));

        /* Should send if mfl code set. It is set by the client version of this extension. */
        conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_512;
        EXPECT_TRUE(s2n_server_max_fragment_length_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_512));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_512;
        EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.send(conn, &stuffer));

        /* Should have correct fragment length */
        uint8_t actual_fragment_length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &actual_fragment_length));
        EXPECT_EQUAL(actual_fragment_length, S2N_TLS_MAX_FRAG_LEN_512);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test receive - does not match requested value
     *
     *= https://tools.ietf.org/rfc/rfc6066#section-4
     *= type=test
     *# Similarly, if a client
     *# receives a maximum fragment length negotiation response that differs
     *# from the length it requested, it MUST also abort the handshake with
     *# an "illegal_parameter" alert.
     */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_512));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;
        EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.send(conn, &stuffer));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_max_fragment_length_extension.recv(conn, &stuffer),
                S2N_ERR_MAX_FRAG_LEN_MISMATCH);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test receive */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_512));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_512;
        EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.send(conn, &stuffer));
        EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        conn->negotiated_mfl_code = 0;
        EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_EQUAL(conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_512);
        EXPECT_EQUAL(conn->max_outgoing_fragment_length, 512);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test receive - existing mfl value */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_1024));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Existing mfl value lower */
        {
            conn->max_outgoing_fragment_length = mfl_code_to_length[S2N_TLS_MAX_FRAG_LEN_512];
            conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;

            EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.send(conn, &stuffer));
            EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            conn->negotiated_mfl_code = 0;
            EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.recv(conn, &stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_EQUAL(conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_1024);
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, mfl_code_to_length[S2N_TLS_MAX_FRAG_LEN_512]);
        };

        /* Existing mfl value higher */
        {
            conn->max_outgoing_fragment_length = mfl_code_to_length[S2N_TLS_MAX_FRAG_LEN_2048];
            conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;

            EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.send(conn, &stuffer));
            EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            conn->negotiated_mfl_code = 0;
            EXPECT_SUCCESS(s2n_server_max_fragment_length_extension.recv(conn, &stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_EQUAL(conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_1024);
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, mfl_code_to_length[S2N_TLS_MAX_FRAG_LEN_1024]);
        };

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    END_TEST();
    return 0;
}
