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

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_blob.h"

#include "crypto/s2n_fips.h"
#include "crypto/s2n_ecc_evp.h"

#include "api/s2n.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_kem.h"

#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"

#include <openssl/pem.h>

/* Included so we can test functions that are otherwise unavailable */
#include "tls/s2n_tls13_handshake.c"

#if !defined(S2N_NO_PQ)

/* "Imports" a PEM encoded private ECC key */
static int read_priv_ecc(EVP_PKEY **pkey, const char *priv_ecc) {
    size_t key_len = sizeof(char) * strlen(priv_ecc);

    BIO *bio = BIO_new_mem_buf(priv_ecc, key_len);
    notnull_check(bio);
    PEM_read_bio_PrivateKey(bio, pkey, 0, NULL);
    /* Caller should assert notnull_check on *pkey */

    /* BIO_free returns 1 for success */
    eq_check(1, BIO_free(bio));

    return 0;
}

static int set_up_conns(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        const char *client_priv_ecc, const char *server_priv_ecc, const struct s2n_kem_group *kem_group,
                struct s2n_blob *pq_shared_secret) {
    /* These parameters would normally be set during the handshake */
    client_conn->secure.chosen_client_kem_group_params = &client_conn->secure.client_kem_group_params[0];
    server_conn->secure.chosen_client_kem_group_params = &server_conn->secure.client_kem_group_params[0];

    server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
    server_conn->secure.chosen_client_kem_group_params->ecc_params.negotiated_curve = kem_group->curve;
    client_conn->secure.server_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
    client_conn->secure.chosen_client_kem_group_params->ecc_params.negotiated_curve = kem_group->curve;

    server_conn->secure.server_kem_group_params.kem_group = kem_group;
    server_conn->secure.chosen_client_kem_group_params->kem_group = kem_group;
    client_conn->secure.server_kem_group_params.kem_group = kem_group;
    client_conn->secure.chosen_client_kem_group_params->kem_group = kem_group;

    server_conn->secure.server_kem_group_params.kem_params.kem = kem_group->kem;
    server_conn->secure.chosen_client_kem_group_params->kem_params.kem = kem_group->kem;
    client_conn->secure.server_kem_group_params.kem_params.kem = kem_group->kem;
    client_conn->secure.chosen_client_kem_group_params->kem_params.kem = kem_group->kem;

    /* PQ shared secret is stored in the server_kem_group_params struct, regardless if connection is client or server */
    GUARD(s2n_dup(pq_shared_secret, &server_conn->secure.server_kem_group_params.kem_params.shared_secret));
    GUARD(s2n_dup(pq_shared_secret, &client_conn->secure.server_kem_group_params.kem_params.shared_secret));

    /* Populate the client's PQ private key with something - it doesn't have to be a
     * legitimate private key since it doesn't get used in the shared secret derivation,
     * but we want to make sure its definitely been freed after shared secret calculation */
    GUARD(s2n_alloc(&client_conn->secure.chosen_client_kem_group_params->kem_params.private_key, 2));
    struct s2n_stuffer private_key_stuffer = {0};
    GUARD(s2n_stuffer_init(&private_key_stuffer,
                           &client_conn->secure.chosen_client_kem_group_params->kem_params.private_key));
    uint8_t fake_private_key[] = {3, 3};
    GUARD(s2n_stuffer_write_bytes(&private_key_stuffer, fake_private_key, 2));

    /* "Import" the provided private ECC keys */
    eq_check(sizeof(char) * strlen(client_priv_ecc), sizeof(char) * strlen(server_priv_ecc));
    GUARD(read_priv_ecc(&client_conn->secure.chosen_client_kem_group_params->ecc_params.evp_pkey, client_priv_ecc));
    notnull_check(client_conn->secure.chosen_client_kem_group_params->ecc_params.evp_pkey);
    GUARD(read_priv_ecc(&server_conn->secure.server_kem_group_params.ecc_params.evp_pkey, server_priv_ecc));
    notnull_check(server_conn->secure.server_kem_group_params.ecc_params.evp_pkey);

    /* Each peer sends its public ECC key to the other */
    struct s2n_stuffer wire;
    struct s2n_blob server_point_blob, client_point_blob;
    uint16_t share_size = kem_group->curve->share_size;

    GUARD(s2n_stuffer_growable_alloc(&wire, 1024));

    GUARD(s2n_ecc_evp_write_params_point(&server_conn->secure.server_kem_group_params.ecc_params, &wire));
    GUARD(s2n_ecc_evp_read_params_point(&wire, share_size, &server_point_blob));
    GUARD(s2n_ecc_evp_parse_params_point(&server_point_blob, &client_conn->secure.server_kem_group_params.ecc_params));

    GUARD(s2n_ecc_evp_write_params_point(&client_conn->secure.chosen_client_kem_group_params->ecc_params, &wire));
    GUARD(s2n_ecc_evp_read_params_point(&wire, share_size, &client_point_blob));
    GUARD(s2n_ecc_evp_parse_params_point(&client_point_blob, &server_conn->secure.chosen_client_kem_group_params->ecc_params));

    GUARD(s2n_stuffer_free(&wire));

    return S2N_SUCCESS;
}

static int assert_kem_group_params_freed(struct s2n_connection *conn) {
    eq_check(NULL,conn->secure.server_kem_group_params.ecc_params.evp_pkey);
    eq_check(NULL,conn->secure.server_kem_group_params.kem_params.shared_secret.data);
    eq_check(0, conn->secure.server_kem_group_params.kem_params.shared_secret.allocated);
    eq_check(NULL, conn->secure.server_kem_group_params.kem_params.private_key.data);
    eq_check(0, conn->secure.server_kem_group_params.kem_params.private_key.allocated);
    eq_check(NULL, conn->secure.server_kem_group_params.kem_params.public_key.data);
    eq_check(0, conn->secure.server_kem_group_params.kem_params.public_key.allocated);

    eq_check(NULL, conn->secure.chosen_client_kem_group_params->ecc_params.evp_pkey);
    eq_check(NULL, conn->secure.chosen_client_kem_group_params->kem_params.shared_secret.data);
    eq_check(0, conn->secure.chosen_client_kem_group_params->kem_params.shared_secret.allocated);
    eq_check(NULL, conn->secure.chosen_client_kem_group_params->kem_params.private_key.data);
    eq_check(0, conn->secure.chosen_client_kem_group_params->kem_params.private_key.allocated);
    eq_check(NULL, conn->secure.chosen_client_kem_group_params->kem_params.public_key.data);
    eq_check(0, conn->secure.chosen_client_kem_group_params->kem_params.public_key.allocated);

    return S2N_SUCCESS;
}

struct hybrid_test_vector {
    const struct s2n_kem_group *kem_group;
    const char *client_ecc_key;
    const char *server_ecc_key;
    struct s2n_blob *pq_secret;
    struct s2n_blob *expected_hybrid_secret;
};

#endif

#define CLIENT_X25519_PRIV_KEY "-----BEGIN PRIVATE KEY-----\n"\
                               "MC4CAQAwBQYDK2VuBCIEIIgzBrAp631nCDaoA7ilx/8S/cW1lddVQOw9869sROBF\n"\
                               "-----END PRIVATE KEY-----"

#define SERVER_X25519_PRIV_KEY "-----BEGIN PRIVATE KEY-----\n"\
                               "MC4CAQAwBQYDK2VuBCIEIIBo+KJ2Zs3vRHQ3sYgHL4zTQPlJPl1y7sW8HT9qRE96\n"\
                               "-----END PRIVATE KEY-----"

#define CLIENT_SECP256R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"\
                                  "BggqhkjOPQMBBw==\n"\
                                  "-----END EC PARAMETERS-----\n"\
                                  "-----BEGIN EC PRIVATE KEY-----\n"\
                                  "MHcCAQEEIFCkEmNXACRbWdizfAKP8/Qvx9aplVxLE+Sm2vmCcsY3oAoGCCqGSM49\n"\
                                  "AwEHoUQDQgAESk526eZ9lf6xrNOiTF8qkYvJDOfc4qqShcbB7qnT67As4pyeQzVm\n"\
                                  "xfMjmXYBOUnPVBL3FKnIk45sDSCfu++gug==\n"\
                                  "-----END EC PRIVATE KEY-----"

#define SERVER_SECP256R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"\
                                  "BggqhkjOPQMBBw==\n"\
                                  "-----END EC PARAMETERS-----\n"\
                                  "-----BEGIN EC PRIVATE KEY-----\n"\
                                  "MHcCAQEEINXLCaZuyYG0HrlSFcHLPFmSnyFm5RqrmyZfgdrxqprXoAoGCCqGSM49\n"\
                                  "AwEHoUQDQgAEMDuuxEQ1yaA13ceuJP+RC0sbf5ksW6DPlL+yXJiD7cUeWUPrtxbP\n"\
                                  "ViSR6ex8fYV69oCHgnDnElfE3xaiXiQWBw==\n"\
                                  "-----END EC PRIVATE KEY-----"

#define X25519_SHARED_SECRET "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910"
#define SECP256R1_SHARED_SECRET "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60"
#define SIKEP434R2_SECRET "35f7f8ff388714dedc41f139078cedc9"
#define X25519_SIKEP434R2_HYBRID_SECRET X25519_SHARED_SECRET SIKEP434R2_SECRET
#define SECP256R1_SIKEP434R2_HYBRID_SECRET SECP256R1_SHARED_SECRET SIKEP434R2_SECRET

int main(int argc, char **argv) {
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }

    S2N_BLOB_FROM_HEX(sikep434r2_secret, SIKEP434R2_SECRET);
    S2N_BLOB_FROM_HEX(x25519_secret, X25519_SHARED_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_secret, SECP256R1_SHARED_SECRET);
    S2N_BLOB_FROM_HEX(x25519_sikep434r2_hybrid_secret, X25519_SIKEP434R2_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_sikep434r2_hybrid_secret,SECP256R1_SIKEP434R2_HYBRID_SECRET);

    const struct hybrid_test_vector x25519_sikep434r2_vector = {
            .kem_group = &s2n_x25519_sike_p434_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &sikep434r2_secret,
            .expected_hybrid_secret = &x25519_sikep434r2_hybrid_secret,
    };

    const struct hybrid_test_vector secp256r1_sikep434r2_vector = {
            .kem_group = &s2n_secp256r1_sike_p434_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &sikep434r2_secret,
            .expected_hybrid_secret = &secp256r1_sikep434r2_hybrid_secret,
    };

    /* Asserting this equality to ensure that this test gets updated if a new kem_group is added */
    EXPECT_EQUAL(2, S2N_SUPPORTED_KEM_GROUPS_COUNT);
    const struct hybrid_test_vector *all_test_vectors[S2N_SUPPORTED_KEM_GROUPS_COUNT] = {
            &x25519_sikep434r2_vector,
            &secp256r1_sikep434r2_vector
    };

    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    {
        /* Happy case for all supported hybrid key calculations */
        for (int i = 0; i < s2n_array_len(all_test_vectors); i++) {
            const struct hybrid_test_vector *test_vector = all_test_vectors[i];
            const struct s2n_kem_group *kem_group = test_vector->kem_group;

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(set_up_conns(client_conn, server_conn, test_vector->client_ecc_key,
                    test_vector->server_ecc_key, kem_group, test_vector->pq_secret));

            DEFER_CLEANUP(struct s2n_blob client_calculated_shared_secret = {0}, s2n_free);
            DEFER_CLEANUP(struct s2n_blob server_calculated_shared_secret = {0}, s2n_free);

            EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_calculated_shared_secret));
            EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(server_conn, &server_calculated_shared_secret));

            S2N_BLOB_EXPECT_EQUAL(client_calculated_shared_secret, server_calculated_shared_secret);
            EXPECT_EQUAL(test_vector->expected_hybrid_secret->size, client_calculated_shared_secret.size);
            EXPECT_BYTEARRAY_EQUAL(test_vector->expected_hybrid_secret->data, client_calculated_shared_secret.data,
                    client_calculated_shared_secret.size);

            EXPECT_SUCCESS(assert_kem_group_params_freed(client_conn));
            EXPECT_SUCCESS(assert_kem_group_params_freed(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }
    {
        /* Various failure cases */
        const struct hybrid_test_vector *test_vector = all_test_vectors[0];
        EXPECT_EQUAL(test_vector->kem_group, &s2n_x25519_sike_p434_r2);

        /* Failures because of NULL arguments */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(NULL, NULL), S2N_ERR_NULL);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, NULL), S2N_ERR_NULL);
        DEFER_CLEANUP(struct s2n_blob client_calculated_shared_secret = {0}, s2n_free);
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(NULL, &client_calculated_shared_secret), S2N_ERR_NULL);

        /* Failure because the chosen_client_kem_group_params is NULL */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        client_conn->secure.chosen_client_kem_group_params = &client_conn->secure.client_kem_group_params[0];

        /* Failures because the kem_group_params aren't set */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        client_conn->secure.server_kem_group_params.ecc_params.negotiated_curve = test_vector->kem_group->curve;
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        client_conn->secure.chosen_client_kem_group_params->ecc_params.negotiated_curve = test_vector->kem_group->curve;

        /* Failures because the ECC private keys are NULL */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        EXPECT_SUCCESS(read_priv_ecc(&client_conn->secure.chosen_client_kem_group_params->ecc_params.evp_pkey, test_vector->client_ecc_key));
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        EXPECT_SUCCESS(read_priv_ecc(&client_conn->secure.server_kem_group_params.ecc_params.evp_pkey, test_vector->server_ecc_key));

        /* Failure because the kem_group is NULL */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        client_conn->secure.server_kem_group_params.kem_group = test_vector->kem_group;

        /* Failure because pq_shared_secret is NULL */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret), S2N_ERR_NULL);
        EXPECT_SUCCESS(s2n_dup(test_vector->pq_secret, &client_conn->secure.server_kem_group_params.kem_params.shared_secret));

        /* Finally, success */
        EXPECT_SUCCESS(s2n_tls13_compute_pq_hybrid_shared_secret(client_conn, &client_calculated_shared_secret));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

#endif

    END_TEST();
}
