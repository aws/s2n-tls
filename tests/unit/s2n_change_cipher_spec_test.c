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

#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t empty_finished_array[S2N_TLS_FINISHED_LEN] = { 0 };

    /* Test s2n_ccs_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_ccs_send(conn));

        uint8_t result;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&conn->handshake.io, &result));
        /* Always 0x01: https://tools.ietf.org/html/rfc5246#section-7.1 */
        EXPECT_EQUAL(result, 0x01);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that s2n_basic_ccs_recv can parse the output of s2n_change_cipher_spec_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_ccs_send(conn));
        EXPECT_SUCCESS(s2n_basic_ccs_recv(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that s2n_basic_ccs_recv errors on wrong change cipher spec types */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->handshake.io, 0));
        EXPECT_FAILURE_WITH_ERRNO(s2n_basic_ccs_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that s2n_client_ccs_recv errors on wrong change cipher spec types */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->handshake.io, 0));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_ccs_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that s2n_server_ccs_recv errors on wrong change cipher spec types */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->handshake.io, 0));
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_ccs_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test s2n_client_ccs_recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* Needed to not break prf */
        conn->secure.cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;

        /* Check preconditions */
        conn->secure.client_sequence_number[0] = 1;
        EXPECT_BYTEARRAY_EQUAL(&conn->handshake.client_finished, &empty_finished_array, S2N_TLS_FINISHED_LEN);
        EXPECT_NOT_EQUAL(conn->client, &conn->secure);
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->alert_in, 1));

        EXPECT_SUCCESS(s2n_ccs_send(conn));
        EXPECT_SUCCESS(s2n_client_ccs_recv(conn));

        /* Check for expected updates */
        EXPECT_EQUAL(conn->secure.client_sequence_number[0], 0);
        EXPECT_BYTEARRAY_NOT_EQUAL(&conn->handshake.client_finished, &empty_finished_array, S2N_TLS_FINISHED_LEN);
        EXPECT_EQUAL(conn->client, &conn->secure);
        EXPECT_FALSE(s2n_stuffer_data_available(&conn->alert_in));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test s2n_server_ccs_recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* Needed to not break prf */
        conn->secure.cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;

        /* Check preconditions */
        conn->secure.server_sequence_number[0] = 1;
        EXPECT_BYTEARRAY_EQUAL(&conn->handshake.server_finished, &empty_finished_array, S2N_TLS_FINISHED_LEN);
        EXPECT_NOT_EQUAL(conn->server, &conn->secure);
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->alert_in, 1));

        EXPECT_SUCCESS(s2n_ccs_send(conn));
        EXPECT_SUCCESS(s2n_server_ccs_recv(conn));

        /* Check for expected updates */
        EXPECT_EQUAL(conn->secure.server_sequence_number[0], 0);
        EXPECT_BYTEARRAY_NOT_EQUAL(&conn->handshake.server_finished, &empty_finished_array, S2N_TLS_FINISHED_LEN);
        EXPECT_EQUAL(conn->server, &conn->secure);
        EXPECT_FALSE(s2n_stuffer_data_available(&conn->alert_in));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
