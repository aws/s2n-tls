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

#include "pq-crypto/s2n_pq.h"
#include "crypto/s2n_ecc_evp.h"
#include "crypto/s2n_hash.h"

#include "api/s2n.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_cipher_suites.h"

#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"

#include <openssl/pem.h>

/* Included so we can test functions that are otherwise unavailable */
#include "tls/s2n_tls13_handshake.c"

S2N_RESULT s2n_tls13_derive_secret(struct s2n_connection *conn, s2n_extract_secret_type_t secret_type,
        s2n_mode mode, struct s2n_blob *secret);

static int read_priv_ecc(EVP_PKEY **pkey, const char *priv_ecc);
static int set_up_conns(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
                        const char *client_priv_ecc, const char *server_priv_ecc, const struct s2n_kem_group *kem_group,
                        struct s2n_blob *pq_shared_secret);
static int assert_kem_group_params_freed(struct s2n_connection *conn);

struct hybrid_test_vector {
    const struct s2n_kem_group *kem_group;
    struct s2n_cipher_suite *cipher_suite;
    const char *transcript;
    const char *client_ecc_key;
    const char *server_ecc_key;
    struct s2n_blob *pq_secret;
    struct s2n_blob *expected_hybrid_secret;
    struct s2n_blob *expected_client_traffic_secret;
    struct s2n_blob *expected_server_traffic_secret;
};

/* PEM-encoded ECC private keys */
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

/* ECDHE shared secrets computed from the private keys above */
#define X25519_SHARED_SECRET "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910"
#define SECP256R1_SHARED_SECRET "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60"

/* PQ shared secrets taken from the first entry in the NIST KAT files */
#define KYBER512R3_SECRET "0A6925676F24B22C286F4C81A4224CEC506C9B257D480E02E3B49F44CAA3237F"

/* Hybrid shared secrets are the concatenation: ECDHE || PQ */
#define X25519_KYBER512R3_HYBRID_SECRET      (X25519_SHARED_SECRET      KYBER512R3_SECRET)
#define SECP256R1_KYBER512R3_HYBRID_SECRET   (SECP256R1_SHARED_SECRET   KYBER512R3_SECRET)


/* The expected traffic secrets were calculated from an independent Python implementation located in the KAT directory,
 * using the ECDHE & PQ secrets defined above. */
#define AES_128_X25519_KYBER512R3_CLIENT_TRAFFIC_SECRET "2d95c9e426941b1cc4a0bd81ee8ba091c6b88edba8c5691dc1b43c0604ff7e74"
#define AES_128_X25519_KYBER512R3_SERVER_TRAFFIC_SECRET "83852c3c0b49f7d260404362eb2d0d91120bc74c149f2224c562d6ac03b29b6e"
#define AES_256_X25519_KYBER512R3_CLIENT_TRAFFIC_SECRET "b929a21fae51da944f32d55976c3da4a2f612f9594f7f4fadd853cab614b3cc4c141d85b920f665eec44c6fbd47bee6b"
#define AES_256_X25519_KYBER512R3_SERVER_TRAFFIC_SECRET "e78dbedab82db5c9fe58db87d0d5cdf031ba7e11dd0cb1c9e2bfe3615569e627142737fc31d659b423b7ebdb476d3672"

#define AES_128_SECP256R1_KYBER512R3_CLIENT_TRAFFIC_SECRET "f14d3873f61f422a0b59100e0b6da0a970300103a634ad444cf4ca78d3ef4fe4"
#define AES_128_SECP256R1_KYBER512R3_SERVER_TRAFFIC_SECRET "04064ddebdbeaa7b51c15d5e919d8a31da94e6fc979fb354ffe453c15abedf3f"
#define AES_256_SECP256R1_KYBER512R3_CLIENT_TRAFFIC_SECRET "48204afd077b9620c6220fbffa30a6de8867d6b4c96e2194cba1220b603b00850baf9dd041ef5074df86bb241023a0cd"
#define AES_256_SECP256R1_KYBER512R3_SERVER_TRAFFIC_SECRET "f2939045fbe7b612da2e96959c64760e763f2f4ef9be049742f51061e063f89668b9acec12440e2b794352f43173243c"



/* A fake transcript string to hash when deriving handshake secrets */
#define FAKE_TRANSCRIPT "client_hello || server_hello"

int main(int argc, char **argv) {
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    S2N_BLOB_FROM_HEX(secp256r1_secret, SECP256R1_SHARED_SECRET);

    S2N_BLOB_FROM_HEX(kyber512r3_secret, KYBER512R3_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_kyber512r3_hybrid_secret, SECP256R1_KYBER512R3_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_kyber512r3_client_secret, AES_128_SECP256R1_KYBER512R3_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_kyber512r3_server_secret, AES_128_SECP256R1_KYBER512R3_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_secp256r1_kyber512r3_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_kyber_512_r3,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &kyber512r3_secret,
            .expected_hybrid_secret = &secp256r1_kyber512r3_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_secp256r1_kyber512r3_client_secret,
            .expected_server_traffic_secret = &aes_128_secp256r1_kyber512r3_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_secp256r1_kyber512r3_client_secret, AES_256_SECP256R1_KYBER512R3_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_secp256r1_kyber512r3_server_secret, AES_256_SECP256R1_KYBER512R3_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_secp256r1_kyber512r3_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_kyber_512_r3,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &kyber512r3_secret,
            .expected_hybrid_secret = &secp256r1_kyber512r3_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_secp256r1_kyber512r3_client_secret,
            .expected_server_traffic_secret = &aes_256_secp256r1_kyber512r3_server_secret,
    };


#if EVP_APIS_SUPPORTED
    /* All x25519 based tls13_kem_groups require EVP_APIS_SUPPORTED */
    S2N_BLOB_FROM_HEX(x25519_secret, X25519_SHARED_SECRET);


    S2N_BLOB_FROM_HEX(x25519_kyber512r3_hybrid_secret, X25519_KYBER512R3_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_kyber512r3_client_secret, AES_128_X25519_KYBER512R3_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_kyber512r3_server_secret, AES_128_X25519_KYBER512R3_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_x25519_kyber512r3_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_kyber_512_r3,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &kyber512r3_secret,
            .expected_hybrid_secret = &x25519_kyber512r3_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_x25519_kyber512r3_client_secret,
            .expected_server_traffic_secret = &aes_128_x25519_kyber512r3_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_x25519_kyber512r3_client_secret, AES_256_X25519_KYBER512R3_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_x25519_kyber512r3_server_secret, AES_256_X25519_KYBER512R3_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_x25519_kyber512r3_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_kyber_512_r3,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &kyber512r3_secret,
            .expected_hybrid_secret = &x25519_kyber512r3_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_x25519_kyber512r3_client_secret,
            .expected_server_traffic_secret = &aes_256_x25519_kyber512r3_server_secret,
    };

#endif

    const struct hybrid_test_vector *all_test_vectors[] = {
            &aes_128_sha_256_secp256r1_kyber512r3_vector,
            &aes_256_sha_384_secp256r1_kyber512r3_vector,
#if EVP_APIS_SUPPORTED
            &aes_128_sha_256_x25519_kyber512r3_vector,
            &aes_256_sha_384_x25519_kyber512r3_vector,
#endif
    };

    EXPECT_EQUAL(s2n_array_len(all_test_vectors), (2 * S2N_SUPPORTED_KEM_GROUPS_COUNT));

    {
        /* Happy cases for computing the hybrid shared secret and client & server traffic secrets */
        for (int i = 0; i < s2n_array_len(all_test_vectors); i++) {
            const struct hybrid_test_vector *test_vector = all_test_vectors[i];
            const struct s2n_kem_group *kem_group = test_vector->kem_group;

            /* Set up connections */
            struct s2n_connection *client_conn = NULL;
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(set_up_conns(client_conn, server_conn, test_vector->client_ecc_key,
                    test_vector->server_ecc_key, kem_group, test_vector->pq_secret));

            /* Calculate the hybrid shared secret */
            DEFER_CLEANUP(struct s2n_blob client_calculated_shared_secret = {0}, s2n_free);
            DEFER_CLEANUP(struct s2n_blob server_calculated_shared_secret = {0}, s2n_free);
            EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_calculated_shared_secret));
            EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(server_conn, &server_calculated_shared_secret));

            /* Assert correctness of hybrid shared secret */
            S2N_BLOB_EXPECT_EQUAL(client_calculated_shared_secret, server_calculated_shared_secret);
            EXPECT_EQUAL(test_vector->expected_hybrid_secret->size, client_calculated_shared_secret.size);
            EXPECT_BYTEARRAY_EQUAL(test_vector->expected_hybrid_secret->data, client_calculated_shared_secret.data,
                    client_calculated_shared_secret.size);

            EXPECT_SUCCESS(assert_kem_group_params_freed(client_conn));
            EXPECT_SUCCESS(assert_kem_group_params_freed(server_conn));

            /* Reset conns. Calculating the shared secret frees necessary params. */
            EXPECT_SUCCESS(set_up_conns(client_conn, server_conn, test_vector->client_ecc_key,
                    test_vector->server_ecc_key, kem_group, test_vector->pq_secret));

            /* Compute the transcript hash, then use the hybrid shared secret to derive
             * the client & server traffic secrets */
            DEFER_CLEANUP(struct s2n_tls13_keys secrets = {0}, s2n_tls13_keys_free);
            EXPECT_SUCCESS(s2n_tls13_keys_init(&secrets, test_vector->cipher_suite->prf_alg));
            client_conn->secure->cipher_suite = test_vector->cipher_suite;

            DEFER_CLEANUP(struct s2n_hash_state hash_state, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&hash_state));
            EXPECT_SUCCESS(s2n_hash_init(&hash_state, secrets.hash_algorithm));
            EXPECT_SUCCESS(s2n_hash_update(&hash_state, test_vector->transcript, strlen(test_vector->transcript)));
            EXPECT_SUCCESS(s2n_hash_digest(&hash_state, client_conn->handshake.hashes->transcript_hash_digest, secrets.size));

            client_conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
            while(s2n_conn_get_current_message_type(client_conn) != SERVER_HELLO) {
                client_conn->handshake.message_number++;
            }

            s2n_tls13_key_blob(client_traffic_secret, secrets.size);
            s2n_tls13_key_blob(server_traffic_secret, secrets.size);
            EXPECT_OK(s2n_tls13_derive_secret(client_conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &client_traffic_secret));
            EXPECT_OK(s2n_tls13_derive_secret(client_conn, S2N_HANDSHAKE_SECRET, S2N_SERVER, &server_traffic_secret));

            /* Assert correctness of traffic secrets */
            EXPECT_EQUAL(test_vector->expected_client_traffic_secret->size, client_traffic_secret.size);
            EXPECT_BYTEARRAY_EQUAL(test_vector->expected_client_traffic_secret->data, client_traffic_secret.data,
                    client_traffic_secret.size);

            EXPECT_EQUAL(test_vector->expected_server_traffic_secret->size, server_traffic_secret.size);
            EXPECT_BYTEARRAY_EQUAL(test_vector->expected_server_traffic_secret->data, server_traffic_secret.data,
                    server_traffic_secret.size);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }
    {
        /* Various failure cases for s2n_tls13_compute_shared_secret() */
        const struct hybrid_test_vector *test_vector = &aes_128_sha_256_secp256r1_kyber512r3_vector;
        s2n_mode modes[] = { S2N_SERVER, S2N_CLIENT };

        for (size_t i = 0; i < s2n_array_len(modes); i++) {
            /* Failures because of NULL arguments */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(NULL, NULL), S2N_ERR_NULL);
            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(modes[i]));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, NULL), S2N_ERR_NULL);
            DEFER_CLEANUP(struct s2n_blob calculated_shared_secret = {0}, s2n_free);
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(NULL, &calculated_shared_secret), S2N_ERR_NULL);

            /* Failures because classic (non-hybrid) parameters were configured */
            conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_SAFETY);
            conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;
            EXPECT_SUCCESS(read_priv_ecc(&conn->kex_params.server_ecc_evp_params.evp_pkey, test_vector->client_ecc_key));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_SAFETY);
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&conn->kex_params.server_ecc_evp_params));

            /* Failure because the chosen_client_kem_group_params is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);

            /* Failures because the kem_group_params aren't set */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve = test_vector->kem_group->curve;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = test_vector->kem_group->curve;

            /* Failures because the ECC private keys are NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(read_priv_ecc(&conn->kex_params.client_kem_group_params.ecc_params.evp_pkey, test_vector->client_ecc_key));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(read_priv_ecc(&conn->kex_params.server_kem_group_params.ecc_params.evp_pkey, test_vector->server_ecc_key));

            /* Failure because pq_shared_secret is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(s2n_dup(test_vector->pq_secret, &conn->kex_params.client_kem_group_params.kem_params.shared_secret));

            /* Failure because the kem_group is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->kex_params.server_kem_group_params.kem_group = test_vector->kem_group;

            /* Finally, success */
            EXPECT_SUCCESS(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    END_TEST();
}

static int read_priv_ecc(EVP_PKEY **pkey, const char *priv_ecc) {
    size_t key_len = sizeof(char) * strlen(priv_ecc);

#if defined(LIBRESSL_VERSION_NUMBER)
    /* LibreSSL's BIO_new_mem_buf() function signature requires a non-const
     * input buffer. */

    DEFER_CLEANUP(struct s2n_blob priv_ecc_blob = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&priv_ecc_blob, key_len));
    for (size_t i = 0; i < key_len; i++) {
        priv_ecc_blob.data[i] = priv_ecc[i];
    }

    BIO *bio = BIO_new_mem_buf((void *)priv_ecc_blob.data, key_len);
#else
    BIO *bio = BIO_new_mem_buf((const void *)priv_ecc, key_len);
#endif

    POSIX_ENSURE_REF(bio);
    PEM_read_bio_PrivateKey(bio, pkey, 0, NULL);
    /* Caller should assert notnull_check on *pkey */

    /* BIO_free returns 1 for success */
    POSIX_ENSURE_EQ(1, BIO_free(bio));

    return 0;
}

static int set_up_conns(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
                        const char *client_priv_ecc, const char *server_priv_ecc, const struct s2n_kem_group *kem_group,
                        struct s2n_blob *pq_shared_secret) {
    /* These parameters would normally be set during the handshake */
    server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
    server_conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
    client_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
    client_conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;

    server_conn->kex_params.server_kem_group_params.kem_group = kem_group;
    server_conn->kex_params.client_kem_group_params.kem_group = kem_group;
    client_conn->kex_params.server_kem_group_params.kem_group = kem_group;
    client_conn->kex_params.client_kem_group_params.kem_group = kem_group;

    server_conn->kex_params.server_kem_group_params.kem_params.kem = kem_group->kem;
    server_conn->kex_params.client_kem_group_params.kem_params.kem = kem_group->kem;
    client_conn->kex_params.server_kem_group_params.kem_params.kem = kem_group->kem;
    client_conn->kex_params.client_kem_group_params.kem_params.kem = kem_group->kem;

    /* During an actual handshake, server will generate the shared secret and store it in chosen_client_kem_group_params,
     * client will decapsulate the ciphertext and store the shared secret in chosen_client_kem_group_params. */
    POSIX_GUARD(s2n_dup(pq_shared_secret, &server_conn->kex_params.client_kem_group_params.kem_params.shared_secret));
    POSIX_GUARD(s2n_dup(pq_shared_secret, &client_conn->kex_params.client_kem_group_params.kem_params.shared_secret));

    /* Populate the client's PQ private key with something - it doesn't have to be a
     * legitimate private key since it doesn't get used in the shared secret derivation,
     * but we want to make sure its definitely been freed after shared secret calculation */
    POSIX_GUARD(s2n_alloc(&client_conn->kex_params.client_kem_group_params.kem_params.private_key, 2));
    struct s2n_stuffer private_key_stuffer = {0};
    POSIX_GUARD(s2n_stuffer_init(&private_key_stuffer,
                           &client_conn->kex_params.client_kem_group_params.kem_params.private_key));
    uint8_t fake_private_key[] = {3, 3};
    POSIX_GUARD(s2n_stuffer_write_bytes(&private_key_stuffer, fake_private_key, 2));

    /* "Import" the provided private ECC keys */
    POSIX_ENSURE_EQ(sizeof(char) * strlen(client_priv_ecc), sizeof(char) * strlen(server_priv_ecc));
    POSIX_GUARD(read_priv_ecc(&client_conn->kex_params.client_kem_group_params.ecc_params.evp_pkey, client_priv_ecc));
    POSIX_ENSURE_REF(client_conn->kex_params.client_kem_group_params.ecc_params.evp_pkey);
    POSIX_GUARD(read_priv_ecc(&server_conn->kex_params.server_kem_group_params.ecc_params.evp_pkey, server_priv_ecc));
    POSIX_ENSURE_REF(server_conn->kex_params.server_kem_group_params.ecc_params.evp_pkey);

    /* Each peer sends its public ECC key to the other */
    struct s2n_stuffer wire;
    struct s2n_blob server_point_blob, client_point_blob;
    uint16_t share_size = kem_group->curve->share_size;

    POSIX_GUARD(s2n_stuffer_growable_alloc(&wire, 1024));

    POSIX_GUARD(s2n_ecc_evp_write_params_point(&server_conn->kex_params.server_kem_group_params.ecc_params, &wire));
    POSIX_GUARD(s2n_ecc_evp_read_params_point(&wire, share_size, &server_point_blob));
    POSIX_GUARD(s2n_ecc_evp_parse_params_point(&server_point_blob, &client_conn->kex_params.server_kem_group_params.ecc_params));

    POSIX_GUARD(s2n_ecc_evp_write_params_point(&client_conn->kex_params.client_kem_group_params.ecc_params, &wire));
    POSIX_GUARD(s2n_ecc_evp_read_params_point(&wire, share_size, &client_point_blob));
    POSIX_GUARD(s2n_ecc_evp_parse_params_point(&client_point_blob, &server_conn->kex_params.client_kem_group_params.ecc_params));

    POSIX_GUARD(s2n_stuffer_free(&wire));

    return S2N_SUCCESS;
}

static int assert_kem_group_params_freed(struct s2n_connection *conn) {
    POSIX_ENSURE_EQ(NULL,conn->kex_params.server_kem_group_params.ecc_params.evp_pkey);
    POSIX_ENSURE_EQ(NULL,conn->kex_params.server_kem_group_params.kem_params.shared_secret.data);
    POSIX_ENSURE_EQ(0, conn->kex_params.server_kem_group_params.kem_params.shared_secret.allocated);
    POSIX_ENSURE_EQ(NULL, conn->kex_params.server_kem_group_params.kem_params.private_key.data);
    POSIX_ENSURE_EQ(0, conn->kex_params.server_kem_group_params.kem_params.private_key.allocated);
    POSIX_ENSURE_EQ(NULL, conn->kex_params.server_kem_group_params.kem_params.public_key.data);
    POSIX_ENSURE_EQ(0, conn->kex_params.server_kem_group_params.kem_params.public_key.allocated);

    POSIX_ENSURE_EQ(NULL, conn->kex_params.client_kem_group_params.ecc_params.evp_pkey);
    POSIX_ENSURE_EQ(NULL, conn->kex_params.client_kem_group_params.kem_params.shared_secret.data);
    POSIX_ENSURE_EQ(0, conn->kex_params.client_kem_group_params.kem_params.shared_secret.allocated);
    POSIX_ENSURE_EQ(NULL, conn->kex_params.client_kem_group_params.kem_params.private_key.data);
    POSIX_ENSURE_EQ(0, conn->kex_params.client_kem_group_params.kem_params.private_key.allocated);
    POSIX_ENSURE_EQ(NULL, conn->kex_params.client_kem_group_params.kem_params.public_key.data);
    POSIX_ENSURE_EQ(0, conn->kex_params.client_kem_group_params.kem_params.public_key.allocated);

    return S2N_SUCCESS;
}
