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

#include "tls/s2n_handshake_hashes.h"

#include "s2n_test.h"
#include "tls/s2n_connection.h"

/* Needed for s2n_handshake_get_hash_state_ptr */
#include "tls/s2n_handshake.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_handshake_hashes_new */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_hashes_new(NULL), S2N_ERR_NULL);

        /* Allocates a new s2n_handshake_hashes struct */
        {
            /* Allocates the struct */
            struct s2n_connection conn = { 0 };
            EXPECT_NULL(conn.handshake.hashes);
            EXPECT_OK(s2n_handshake_hashes_new(&conn.handshake.hashes));
            EXPECT_NOT_NULL(conn.handshake.hashes);

            uint8_t data[100] = { 0 };

            /* Allocates all hashes */
            for (s2n_hash_algorithm alg = 0; alg < S2N_HASH_SENTINEL; alg++) {
                if (alg == S2N_HASH_NONE) {
                    continue;
                }

                uint8_t size = 0;
                EXPECT_SUCCESS(s2n_hash_digest_size(alg, &size));
                EXPECT_TRUE(size < sizeof(data));

                struct s2n_hash_state *hash_state = NULL;
                EXPECT_SUCCESS(s2n_handshake_get_hash_state_ptr(&conn, alg, &hash_state));

                /* Hash is setup / useable */
                EXPECT_SUCCESS(s2n_hash_digest(hash_state, data, size));
            }

            s2n_handshake_hashes_free(&conn.handshake.hashes);
        };
    };

    /* Test s2n_handshake_hashes_wipe */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_hashes_wipe(NULL), S2N_ERR_NULL);

        /* Resets all hashes */
        {
            struct s2n_connection conn = { 0 };
            EXPECT_OK(s2n_handshake_hashes_new(&conn.handshake.hashes));
            EXPECT_NOT_NULL(conn.handshake.hashes);

            uint8_t data[100] = { 0 };

            for (s2n_hash_algorithm alg = 0; alg < S2N_HASH_SENTINEL; alg++) {
                if (alg == S2N_HASH_NONE) {
                    continue;
                }

                uint8_t size = 0;
                EXPECT_SUCCESS(s2n_hash_digest_size(alg, &size));
                EXPECT_TRUE(size < sizeof(data));

                struct s2n_hash_state *hash_state = NULL;
                EXPECT_SUCCESS(s2n_handshake_get_hash_state_ptr(&conn, alg, &hash_state));
                EXPECT_SUCCESS(s2n_hash_digest(hash_state, data, size));

                /* Can't calculate the digest again: only one digest allowed per hash */
                EXPECT_FAILURE_WITH_ERRNO(s2n_hash_digest(hash_state, data, size), S2N_ERR_HASH_NOT_READY);

                /* Wiping the hashes allows them to be successfully reused */
                EXPECT_OK(s2n_handshake_hashes_wipe(conn.handshake.hashes));
                EXPECT_SUCCESS(s2n_hash_digest(hash_state, data, size));
            }

            s2n_handshake_hashes_free(&conn.handshake.hashes);
        };
    };

    /* Test s2n_handshake_hashes_free */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_hashes_free(NULL), S2N_ERR_NULL);

        /* Frees the hashes with no memory leaks */
        {
            struct s2n_handshake_hashes *hashes = NULL;
            EXPECT_OK(s2n_handshake_hashes_new(&hashes));
            EXPECT_NOT_NULL(hashes);

            EXPECT_OK(s2n_handshake_hashes_free(&hashes));
            EXPECT_NULL(hashes);
        };
    };

    /* Test s2n_handshake_hashes connection lifecycle */
    {
        uint8_t digest[SHA256_DIGEST_LENGTH] = { 0 };

        /* A new connection's hashes are properly set up and can be used. */
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        struct s2n_hash_state *hash_state = NULL;
        EXPECT_SUCCESS(s2n_handshake_get_hash_state_ptr(conn, S2N_HASH_SHA256, &hash_state));
        EXPECT_NOT_NULL(hash_state);
        EXPECT_SUCCESS(s2n_hash_digest(hash_state, digest, SHA256_DIGEST_LENGTH));
        EXPECT_FAILURE_WITH_ERRNO(s2n_hash_digest(hash_state, digest, SHA256_DIGEST_LENGTH), S2N_ERR_HASH_NOT_READY);

        /* A wiped connection's hashes can be reused. */
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(s2n_handshake_get_hash_state_ptr(conn, S2N_HASH_SHA256, &hash_state));
        EXPECT_NOT_NULL(hash_state);
        EXPECT_SUCCESS(s2n_hash_digest(hash_state, digest, SHA256_DIGEST_LENGTH));

        /* Freeing the handshake frees the hashes */
        EXPECT_SUCCESS(s2n_connection_free_handshake(conn));
        EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_get_hash_state_ptr(conn, S2N_HASH_SHA256, &hash_state), S2N_ERR_NULL);
        EXPECT_NULL(conn->handshake.hashes);

        /* Wiping the connection should restore the freed hashes */
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(s2n_handshake_get_hash_state_ptr(conn, S2N_HASH_SHA256, &hash_state));
        EXPECT_NOT_NULL(hash_state);
        EXPECT_SUCCESS(s2n_hash_digest(hash_state, digest, SHA256_DIGEST_LENGTH));

        /* Freeing the connection should free the hashes */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}
