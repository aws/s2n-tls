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
#include "tls/extensions/s2n_client_max_frag_len.h"
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

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_EXT_NONE));
        EXPECT_FALSE(s2n_client_max_frag_len_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_512));
        EXPECT_TRUE(s2n_client_max_frag_len_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_512));
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.send(conn, &stuffer));

        /* Should have correct fragment length */
        uint8_t actual_frag_len;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &actual_frag_len));
        EXPECT_EQUAL(actual_frag_len, S2N_TLS_MAX_FRAG_LEN_512);
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test receive - accept_mfl not set */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config, S2N_TLS_MAX_FRAG_LEN_512));
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.send(conn, &stuffer));

        /* Ignore fragment length if not accepting max fragment length */
        EXPECT_FALSE(config->accept_mfl);
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_EXT_NONE);
        EXPECT_EQUAL(conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test receive - invalid mfl code
     *
     *= https://tools.ietf.org/rfc/rfc6066#section-4
     *= type=test
     *# If a server receives a maximum fragment length negotiation request
     *# for a value other than the allowed values, it MUST abort the
     *# handshake with an "illegal_parameter" alert.
     */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(config));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Send invalid mfl code */
        conn->config->mfl_code = UINT8_MAX;
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.send(conn, &stuffer));

        /* Ignore invalid mfl code */
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_EXT_NONE);
        EXPECT_EQUAL(conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test receive */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(config));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(conn->config, S2N_TLS_MAX_FRAG_LEN_512));
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.send(conn, &stuffer));

        /* Accept valid mfl code */
        EXPECT_SUCCESS(s2n_client_max_frag_len_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_512);
        EXPECT_EQUAL(conn->max_outgoing_fragment_length, mfl_code_to_length[S2N_TLS_MAX_FRAG_LEN_512]);
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    END_TEST();
    return 0;
}
