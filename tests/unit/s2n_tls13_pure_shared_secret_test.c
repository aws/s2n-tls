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
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13_handshake.c"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_tls13_derive_secret(struct s2n_connection *conn, s2n_extract_secret_type_t secret_type,
        s2n_mode mode, struct s2n_blob *secret);

/* PQ shared secret taken from Python-generated KAT */
#define MLKEM1024_SECRET "B408D5D115713F0A93047DBBEA832E4340787686D59A9A2D106BD662BA0AA035"

/* Expected traffic secrets from Python KAT for MLKEM1024 + AES_128_GCM_SHA256 */
#define AES_128_MLKEM1024_CLIENT_TRAFFIC_SECRET "8ab94e7f368d1327b624defe057dc31a8f103184f4ac28ff8026a75315a7f8b5"
#define AES_128_MLKEM1024_SERVER_TRAFFIC_SECRET "204972304f3858ccd147b37b9f0537814276507ee9957e82517133932df49d1d"

/* Expected traffic secrets from Python KAT for MLKEM1024 + AES_256_GCM_SHA384 */
#define AES_256_MLKEM1024_CLIENT_TRAFFIC_SECRET "c7b966187dc424ac82656bece5665b0f230b783328f3e38ece38e74768b61f694f3c661214cd9f0a7bece1baeb93f3a0"
#define AES_256_MLKEM1024_SERVER_TRAFFIC_SECRET "f920fdabeb2c1b2ca5f016c2124a84f88a18243c24f004bd67a2db238bf49ce02d97259c43ef09e62394a18650dd59ed"

/* Fake transcript string for hashing */
#define FAKE_TRANSCRIPT "client_hello || server_hello"

struct pure_pq_test_vector {
    struct s2n_cipher_suite *cipher_suite;
    const char *transcript;
    const struct s2n_kem_group *kem_group;
    struct s2n_blob *pq_secret;
    struct s2n_blob *expected_client_traffic_secret;
    struct s2n_blob *expected_server_traffic_secret;
};

static int set_up_pure_pq_conns(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        const struct s2n_kem_group *kem_group, struct s2n_blob *pq_shared_secret);

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Prepare blobs */
    S2N_BLOB_FROM_HEX(mlkem1024_secret, MLKEM1024_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_mlkem1024_client_secret, AES_128_MLKEM1024_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_mlkem1024_server_secret, AES_128_MLKEM1024_SERVER_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_mlkem1024_client_secret, AES_256_MLKEM1024_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_mlkem1024_server_secret, AES_256_MLKEM1024_SERVER_TRAFFIC_SECRET);

    const struct pure_pq_test_vector aes_128_sha_256_mlkem1024_vector = {
        .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_pure_mlkem_1024,
        .pq_secret = &mlkem1024_secret,
        .expected_client_traffic_secret = &aes_128_mlkem1024_client_secret,
        .expected_server_traffic_secret = &aes_128_mlkem1024_server_secret,
    };

    const struct pure_pq_test_vector aes_256_sha_384_mlkem1024_vector = {
        .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_pure_mlkem_1024,
        .pq_secret = &mlkem1024_secret,
        .expected_client_traffic_secret = &aes_256_mlkem1024_client_secret,
        .expected_server_traffic_secret = &aes_256_mlkem1024_server_secret,
    };

    const struct pure_pq_test_vector *all_test_vectors[] = {
        &aes_128_sha_256_mlkem1024_vector,
        &aes_256_sha_384_mlkem1024_vector,
    };

    /* Loop through tests */
    for (int i = 0; i < s2n_array_len(all_test_vectors); i++) {
        const struct pure_pq_test_vector *test_vector = all_test_vectors[i];

        /* Skip if ML-KEM is not available */
        if (!s2n_kem_group_is_available(test_vector->kem_group)) {
            continue;
        }

        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        EXPECT_SUCCESS(set_up_pure_pq_conns(client_conn, server_conn,
                test_vector->kem_group, test_vector->pq_secret));

        /* Compute shared secret */
        DEFER_CLEANUP(struct s2n_blob client_calculated_shared_secret = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob server_calculated_shared_secret = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_calculated_shared_secret));
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(server_conn, &server_calculated_shared_secret));

        S2N_BLOB_EXPECT_EQUAL(client_calculated_shared_secret, server_calculated_shared_secret);

        /* Reset conns for traffic secret derivation */
        EXPECT_SUCCESS(set_up_pure_pq_conns(client_conn, server_conn,
                test_vector->kem_group, test_vector->pq_secret));

        /* Compute transcript hash for both client and server */
        DEFER_CLEANUP(struct s2n_tls13_keys secrets = { 0 }, s2n_tls13_keys_free);
        EXPECT_SUCCESS(s2n_tls13_keys_init(&secrets, test_vector->cipher_suite->prf_alg));
        client_conn->secure->cipher_suite = test_vector->cipher_suite;

        DEFER_CLEANUP(struct s2n_hash_state hash_state, s2n_hash_free);
        EXPECT_SUCCESS(s2n_hash_new(&hash_state));
        EXPECT_SUCCESS(s2n_hash_init(&hash_state, secrets.hash_algorithm));
        EXPECT_SUCCESS(s2n_hash_update(&hash_state, test_vector->transcript, strlen(test_vector->transcript)));
        EXPECT_SUCCESS(s2n_hash_digest(&hash_state, client_conn->handshake.hashes->transcript_hash_digest, secrets.size));

        client_conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        while (s2n_conn_get_current_message_type(client_conn) != SERVER_HELLO) {
            client_conn->handshake.message_number++;
        }

        /* Derive traffic secrets */
        s2n_tls13_key_blob(client_traffic_secret, secrets.size);
        s2n_tls13_key_blob(server_traffic_secret, secrets.size);
        EXPECT_OK(s2n_tls13_derive_secret(client_conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &client_traffic_secret));
        EXPECT_OK(s2n_tls13_derive_secret(client_conn, S2N_HANDSHAKE_SECRET, S2N_SERVER, &server_traffic_secret));

        EXPECT_EQUAL(test_vector->expected_client_traffic_secret->size, client_traffic_secret.size);
        EXPECT_BYTEARRAY_EQUAL(test_vector->expected_client_traffic_secret->data, client_traffic_secret.data,
                client_traffic_secret.size);

        EXPECT_EQUAL(test_vector->expected_server_traffic_secret->size, server_traffic_secret.size);
        EXPECT_BYTEARRAY_EQUAL(test_vector->expected_server_traffic_secret->data, server_traffic_secret.data,
                server_traffic_secret.size);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
}

static int set_up_pure_pq_conns(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        const struct s2n_kem_group *kem_group, struct s2n_blob *pq_shared_secret)
{
    /* Assign KEM groups */
    server_conn->kex_params.server_kem_group_params.kem_group = kem_group;
    server_conn->kex_params.client_kem_group_params.kem_group = kem_group;
    client_conn->kex_params.server_kem_group_params.kem_group = kem_group;
    client_conn->kex_params.client_kem_group_params.kem_group = kem_group;

    /* Assign KEM params */
    server_conn->kex_params.server_kem_group_params.kem_params.kem = kem_group->kem;
    server_conn->kex_params.client_kem_group_params.kem_params.kem = kem_group->kem;
    client_conn->kex_params.server_kem_group_params.kem_params.kem = kem_group->kem;
    client_conn->kex_params.client_kem_group_params.kem_params.kem = kem_group->kem;

    /* Copy shared secret into both ends */
    POSIX_GUARD(s2n_dup(pq_shared_secret, &server_conn->kex_params.client_kem_group_params.kem_params.shared_secret));
    POSIX_GUARD(s2n_dup(pq_shared_secret, &client_conn->kex_params.client_kem_group_params.kem_params.shared_secret));

    return S2N_SUCCESS;
}
