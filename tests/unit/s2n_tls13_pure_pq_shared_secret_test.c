/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
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
#include "crypto/s2n_pq.h"
#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13_handshake.c"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

#define MLKEM1024_SECRET "B408D5D115713F0A93047DBBEA832E4340787686D59A9A2D106BD662BA0AA035"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: TLS 1.3 pure ML-KEM-1024 shared secret computation */
    {
        S2N_BLOB_FROM_HEX(expected_secret, MLKEM1024_SECRET);

        DEFER_CLEANUP(struct s2n_connection *client_conn = NULL, s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = NULL, s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        client_conn->kex_params.server_kem_group_params.kem_group = &s2n_pure_mlkem_1024;
        client_conn->kex_params.client_kem_group_params.kem_group = &s2n_pure_mlkem_1024;
        server_conn->kex_params.server_kem_group_params.kem_group = &s2n_pure_mlkem_1024;
        server_conn->kex_params.client_kem_group_params.kem_group = &s2n_pure_mlkem_1024;

        client_conn->kex_params.server_kem_group_params.kem_params.kem = s2n_pure_mlkem_1024.kem;
        client_conn->kex_params.client_kem_group_params.kem_params.kem = s2n_pure_mlkem_1024.kem;
        server_conn->kex_params.server_kem_group_params.kem_params.kem = s2n_pure_mlkem_1024.kem;
        server_conn->kex_params.client_kem_group_params.kem_params.kem = s2n_pure_mlkem_1024.kem;

        POSIX_GUARD(s2n_dup(&expected_secret,
                &client_conn->kex_params.client_kem_group_params.kem_params.shared_secret));
        POSIX_GUARD(s2n_dup(&expected_secret,
                &server_conn->kex_params.client_kem_group_params.kem_params.shared_secret));

        DEFER_CLEANUP(struct s2n_blob client_secret = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob server_secret = { 0 }, s2n_free);

        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_secret));
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(server_conn, &server_secret));

        S2N_BLOB_EXPECT_EQUAL(client_secret, server_secret);

        EXPECT_EQUAL(client_secret.size, expected_secret.size);
        EXPECT_BYTEARRAY_EQUAL(client_secret.data, expected_secret.data, expected_secret.size);
    };

    END_TEST();
}
