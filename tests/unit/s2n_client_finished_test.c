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

    /* Send and receive correct ClientFinished */
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
        POSIX_GUARD(s2n_prf_client_finished(server_conn));

        EXPECT_EQUAL(client_conn->client, client_conn->initial);

        EXPECT_SUCCESS(s2n_client_finished_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_finished_recv(server_conn));

        EXPECT_EQUAL(client_conn->client, client_conn->secure);
    };

    /* Server rejects incorrect ClientFinished */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        server_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        server_conn->actual_protocol_version = S2N_TLS12;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        client_conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
        client_conn->actual_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_client_finished_send(client_conn));

        /* s2n_client_finished_send calculates and writes the handshake verify data
         * to the io stuffer. Since the verify data is at least 12 bytes long
         * we can flip a random bit in that range to mutate it. */
        client_conn->handshake.io.blob.data[10]++;
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_finished_recv(server_conn), S2N_ERR_BAD_MESSAGE);
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
        POSIX_GUARD(s2n_prf_client_finished(server_conn));
        server_conn->handshake.finished_len = 1;

        EXPECT_SUCCESS(s2n_client_finished_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_finished_recv(server_conn), S2N_ERR_SAFETY);
    };

    END_TEST();
}
