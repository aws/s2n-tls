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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Send and receive correct ServerFinished */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        server_conn->actual_protocol_version = S2N_TLS12;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        client_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        client_conn->actual_protocol_version = S2N_TLS12;

        /* Calculate valid verify_data */
        POSIX_GUARD(s2n_prf_server_finished(client_conn));

        EXPECT_EQUAL(server_conn->server, server_conn->initial);

        EXPECT_SUCCESS(s2n_server_finished_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_server_finished_recv(client_conn));

        EXPECT_EQUAL(server_conn->server, server_conn->secure);
    };

    /* Client rejects incorrect ServerFinished */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        server_conn->actual_protocol_version = S2N_TLS12;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        client_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        client_conn->actual_protocol_version = S2N_TLS12;

        /* Mutate valid verify_data */
        POSIX_GUARD(s2n_prf_server_finished(client_conn));
        client_conn->handshake.server_finished[0]++;

        EXPECT_SUCCESS(s2n_server_finished_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_finished_recv(client_conn), S2N_ERR_BAD_MESSAGE);
    };

    /* Error if local verify_data has wrong length */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        server_conn->actual_protocol_version = S2N_TLS12;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        client_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        client_conn->actual_protocol_version = S2N_TLS12;

        /* Change the length of valid verify_data */
        POSIX_GUARD(s2n_prf_server_finished(client_conn));
        client_conn->handshake.finished_len = 1;

        EXPECT_SUCCESS(s2n_server_finished_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_finished_recv(client_conn), S2N_ERR_SAFETY);
    };

    END_TEST();
}
