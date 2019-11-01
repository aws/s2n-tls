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
#include "tls/s2n_tls.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

static int reset_stuffers(struct s2n_stuffer *reread, struct s2n_stuffer *wipe)
{
    GUARD(s2n_stuffer_reread(reread));
    GUARD(s2n_stuffer_wipe(wipe));
    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_tls13_server_finished_send and s2n_tls13_server_finished_recv */
    {
        struct s2n_cipher_suite cipher_suites[] = {
            s2n_tls13_aes_128_gcm_sha256,
            s2n_tls13_aes_256_gcm_sha384,
            s2n_tls13_chacha20_poly1305_sha256
        };

        int hash_sizes[] = {
            32, 48, 32
        };

        for (int i = 0; i < 3; i++) {
            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));

            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure.cipher_suite = &cipher_suites[i];

            int hash_size = hash_sizes[i];

            EXPECT_SUCCESS(s2n_tls13_server_finished_send(server_conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), hash_size);

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure.cipher_suite = &cipher_suites[i];

            EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, hash_size));
            EXPECT_SUCCESS(s2n_tls13_server_finished_recv(client_conn));

            /* Expect failure if verify has a missing byte */
            EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, hash_size - 1));
            EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

            /* Expect failure if verify have additional byte */
            EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, hash_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
            EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

            /* Expect failure if verify on wire is modified by 1 bit */
            EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, hash_size));
            client_conn->handshake.io.blob.data[0] ^= 1;
            EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

            /* Expect failure if finished key differs */
            EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, hash_size));
            client_conn->handshake.server_finished[0] ^= 1;
            EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    /* Test that they can only run in TLS 1.3 mode */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));
        server_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        EXPECT_FAILURE(s2n_tls13_server_finished_send(server_conn));

        /* now with TLS 1.3, server finished send can run */
        server_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_tls13_server_finished_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), 48);

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, 48));
        EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test for failure cases if cipher suites are incompatible */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));

        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        EXPECT_SUCCESS(s2n_tls13_server_finished_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), 32);

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, 32));
        EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test for failure cases when finished secret key differs */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));

        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        EXPECT_SUCCESS(s2n_tls13_server_finished_send(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), 48);

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        for (int i = 0; i < 48; i++) {
            EXPECT_SUCCESS(reset_stuffers(&server_conn->handshake.io, &client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, 48));

            /* flip a bit to test failure */
            client_conn->handshake.server_finished[i] ^= 1;
            EXPECT_FAILURE(s2n_tls13_server_finished_recv(client_conn));

            /* flip the bit back */
            client_conn->handshake.server_finished[i] ^= 1;
        }

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
    return 0;
}
