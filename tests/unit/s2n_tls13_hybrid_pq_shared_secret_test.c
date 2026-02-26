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

#include <openssl/pem.h>

#include "api/s2n.h"
#include "crypto/s2n_ecc_evp.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_pq.h"
#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_kem.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

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

#define S2N_HYBRID_KEM_GROUPS_COUNT 3

/* PEM-encoded ECC private keys generated using openssl commands like:
 *
 * $ openssl ecparam -name ${CURVE_NAME} -genkey
 */
#define CLIENT_X25519_PRIV_KEY "-----BEGIN PRIVATE KEY-----\n"                                      \
                               "MC4CAQAwBQYDK2VuBCIEIIgzBrAp631nCDaoA7ilx/8S/cW1lddVQOw9869sROBF\n" \
                               "-----END PRIVATE KEY-----"

#define SERVER_X25519_PRIV_KEY "-----BEGIN PRIVATE KEY-----\n"                                      \
                               "MC4CAQAwBQYDK2VuBCIEIIBo+KJ2Zs3vRHQ3sYgHL4zTQPlJPl1y7sW8HT9qRE96\n" \
                               "-----END PRIVATE KEY-----"

#define CLIENT_SECP256R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"                                    \
                                  "BggqhkjOPQMBBw==\n"                                                 \
                                  "-----END EC PARAMETERS-----\n"                                      \
                                  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
                                  "MHcCAQEEIFCkEmNXACRbWdizfAKP8/Qvx9aplVxLE+Sm2vmCcsY3oAoGCCqGSM49\n" \
                                  "AwEHoUQDQgAESk526eZ9lf6xrNOiTF8qkYvJDOfc4qqShcbB7qnT67As4pyeQzVm\n" \
                                  "xfMjmXYBOUnPVBL3FKnIk45sDSCfu++gug==\n"                             \
                                  "-----END EC PRIVATE KEY-----"

#define SERVER_SECP256R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"                                    \
                                  "BggqhkjOPQMBBw==\n"                                                 \
                                  "-----END EC PARAMETERS-----\n"                                      \
                                  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
                                  "MHcCAQEEINXLCaZuyYG0HrlSFcHLPFmSnyFm5RqrmyZfgdrxqprXoAoGCCqGSM49\n" \
                                  "AwEHoUQDQgAEMDuuxEQ1yaA13ceuJP+RC0sbf5ksW6DPlL+yXJiD7cUeWUPrtxbP\n" \
                                  "ViSR6ex8fYV69oCHgnDnElfE3xaiXiQWBw==\n"                             \
                                  "-----END EC PRIVATE KEY-----"

#define CLIENT_SECP384R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"                                    \
                                  "BgUrgQQAIg==\n"                                                     \
                                  "-----END EC PARAMETERS-----\n"                                      \
                                  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
                                  "MIGkAgEBBDCq+TiiEmbFT2xiIj1s6q+Tk/qw3DRHrpH1SWb36XNmv+FcASF24EmU\n" \
                                  "QSffpZLGRk6gBwYFK4EEACKhZANiAAQp0Y+a+SfYB9V/TDF9jzwoa5ccedThv4mY\n" \
                                  "ddHwoynSGE95n7f8T25/276MHOoi79P5WP82aiLoIOL68IVflQPLMPFYnN9BumVo\n" \
                                  "UjmCWR9yl8gEBWl4teiaRvvMf2i7ayM=\n"                                 \
                                  "-----END EC PRIVATE KEY-----\n"

#define SERVER_SECP384R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"                                    \
                                  "BgUrgQQAIg==\n"                                                     \
                                  "-----END EC PARAMETERS-----\n"                                      \
                                  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
                                  "MIGkAgEBBDATrNZMWEQHj/8iJFBUy+X3fG1zvhZE9zWX5qHVkxlSH3iY14y7NBhh\n" \
                                  "6UQIrBRiPHagBwYFK4EEACKhZANiAAQlvEGmcz6hluErpKBxJPNRh6wf6qb9ceu7\n" \
                                  "8CwgDMHbLFYzrnLPDDIaUVRfkrfYBEtL9WSJZUIelJIw8hK1qoXkaL+D/aKWz7Wm\n" \
                                  "9MWDKS15M62Q2PAfjjFoO69nFPHcqM0=\n"                                 \
                                  "-----END EC PRIVATE KEY-----\n"

#define CLIENT_SECP521R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"                                    \
                                  "BgUrgQQAIw==\n"                                                     \
                                  "-----END EC PARAMETERS-----\n"                                      \
                                  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
                                  "MIHcAgEBBEIB4Cj94bbC/xIDnrd8kqlmfum2L6C6l2uajrPXR5dnartodZl1Sswg\n" \
                                  "IWSimNW2k1LELdDQC+MfOIjCopANRFH5fgmgBwYFK4EEACOhgYkDgYYABAF+9lQh\n" \
                                  "7WgX0eNpMQEQmMDMiwfb/7QxmlVxHvl/1+Bh89pxzLwrFjGGKmwgSV5f85/vNQdo\n" \
                                  "jAhzWUTIes3j/qWmBAB63FI2S+yBkhD1tfZl4sUUoLX20T1OexFEk0RRPQI6oCdZ\n" \
                                  "TFusCC+4trkSnj9gEgLFfwShb0kUFYoBpJzmVFN1BA==\n"                     \
                                  "-----END EC PRIVATE KEY-----\n"

#define SERVER_SECP521R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"                                    \
                                  "BgUrgQQAIw==\n"                                                     \
                                  "-----END EC PARAMETERS-----\n"                                      \
                                  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
                                  "MIHcAgEBBEIAYwEZ+1dvjYoQZhu+0ZS+gY1uB0ON1YvtblgWJI/Blw/pXv4oUfFX\n" \
                                  "QLXyjkx5ctQzNDKIGEdZ5BcSkBZ+3mJXyuagBwYFK4EEACOhgYkDgYYABACoLmHw\n" \
                                  "oiWFRf4LAKWTFXEAmx7mVLHvP5YY01PWbbjY2AL3+O5CMBODj3rGuL0lJgRWondF\n" \
                                  "R6KTS/zw9VK4gyDOXAAyeB4EfVx47ANXQO7bB+dS6WrmUAPY9L6MYkoqngorCf5j\n" \
                                  "A24QOAiftXdo/IcvXOephiffhGigGetVLd1tIfNM/w==\n"                     \
                                  "-----END EC PRIVATE KEY-----\n"

/* ECDHE shared secrets computed from the private keys above using openssl commands like:
 *
 * $ openssl pkeyutl -derive -inkey ${CLIENT_PRIV}.pem -peerkey ${SERVER_PUB}.pem -hexdump
 */
#define X25519_SHARED_SECRET    "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910"
#define SECP256R1_SHARED_SECRET "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60"
#define SECP384R1_SHARED_SECRET "b72536062cd8e8eced91046e33413b027cabde0576747aa47863b8dcb914100585c600fafc8ff4927a34abb0aa6b3b68"
#define SECP521R1_SHARED_SECRET "009643bb20199e8f408b7c19bb98d1d19f0cef9104e2ec790c398c6abe7dc5cf47afb96de70aa14c86bc546a12f9ea3abbf2eec399b4d586083114cbc37f53ed2d8b"

/* PQ shared secrets taken from the first entry in the NIST KAT files */
#define MLKEM768_SECRET  "B408D5D115713F0A93047DBBEA832E4340787686D59A9A2D106BD662BA0AA035"
#define MLKEM1024_SECRET "23f211b84a6ee20c8c29f6e5314c91b414e940513d380add17bd724ab3a13a52"

#define X25519_MLKEM768_HYBRID_SECRET     (MLKEM768_SECRET X25519_SHARED_SECRET)
#define SECP256R1_MLKEM768_HYBRID_SECRET  (SECP256R1_SHARED_SECRET MLKEM768_SECRET)
#define SECP384R1_MLKEM1024_HYBRID_SECRET (SECP384R1_SHARED_SECRET MLKEM1024_SECRET)

/* The expected traffic secrets were calculated from an independent Python implementation located in the KAT directory,
 * using the ECDHE & PQ secrets defined above. */
#define AES_128_SECP256R1_MLKEM768_CLIENT_TRAFFIC_SECRET "e3b086562f8dc237a9dc8710f345821c871417bd57a64a1966860f1f06bcd5dc"
#define AES_128_SECP256R1_MLKEM768_SERVER_TRAFFIC_SECRET "eb3f47d5cc09234957543e1160dde10cc86b817f31c43d5e8af8cdd6167b0336"
#define AES_256_SECP256R1_MLKEM768_CLIENT_TRAFFIC_SECRET "9e65803eeb8324eb5faea82be52c266e0bf8ac398f091db73a48e68ee2ff0a91915b3f1f4e9907e33543a9ebb1f7a748"
#define AES_256_SECP256R1_MLKEM768_SERVER_TRAFFIC_SECRET "cb8fc8707f294e3ab9b98f0d873b1e1c5d740ecd254c67fcca44b5444742bf958102be17beb5c89ae08b8b31191d9137"

#define AES_128_X25519_MLKEM768_CLIENT_TRAFFIC_SECRET "8bf7f5f36cdece4ca1439e14e9b585cd5c2c11753ce53733da771c89ba7d8162"
#define AES_128_X25519_MLKEM768_SERVER_TRAFFIC_SECRET "c9221c9f9fad66ac7ae568e46695229eaf95196819c2bb997469f010075b953e"
#define AES_256_X25519_MLKEM768_CLIENT_TRAFFIC_SECRET "44eb9e15ef082936fe7a2c169be644ff16b47fb2a91f7223069cbd8d9b063a034f0936234e60a733a30db6d7226d984d"
#define AES_256_X25519_MLKEM768_SERVER_TRAFFIC_SECRET "852b46f0e3cdc222badc0b85f4cfb4f332c2d8ea8c9695d6024e129b5056d2c534191ee76bff50148f19a88f81897112"

#define AES_128_SECP384R1_MLKEM1024_CLIENT_TRAFFIC_SECRET "367b160926dc977e255fa5fdd15c51a3942f98a492db05d74777ed4498882179"
#define AES_128_SECP384R1_MLKEM1024_SERVER_TRAFFIC_SECRET "93c1dcb54fa694957f8decde496944533d64a6e11884bfb8c928cd3b9e954836"
#define AES_256_SECP384R1_MLKEM1024_CLIENT_TRAFFIC_SECRET "900c6409a1f1d748006759b8276a2ae7b74dca44d9c4e52083952e7cf1c868cba34c270b802dea59a7a8a00b919ff061"
#define AES_256_SECP384R1_MLKEM1024_SERVER_TRAFFIC_SECRET "ccabea1600385fdd3587429d701aae0efcf6acac0bab0f194d571d78fa8755a0d0a58364c07c14fbe288a67843b68530"

/* A fake transcript string to hash when deriving handshake secrets */
#define FAKE_TRANSCRIPT "client_hello || server_hello"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    S2N_BLOB_FROM_HEX(secp256r1_secret, SECP256R1_SHARED_SECRET);
    S2N_BLOB_FROM_HEX(x25519_secret, X25519_SHARED_SECRET);

    S2N_BLOB_FROM_HEX(mlkem768_secret, MLKEM768_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_mlkem768_hybrid_secret, SECP256R1_MLKEM768_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(x25519_mlkem768_hybrid_secret, X25519_MLKEM768_HYBRID_SECRET);

    S2N_BLOB_FROM_HEX(aes_128_secp256r1_mlkem768_client_secret, AES_128_SECP256R1_MLKEM768_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_mlkem768_server_secret, AES_128_SECP256R1_MLKEM768_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_secp256r1_mlkem768_vector = {
        .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_secp256r1_mlkem_768,
        .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
        .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
        .pq_secret = &mlkem768_secret,
        .expected_hybrid_secret = &secp256r1_mlkem768_hybrid_secret,
        .expected_client_traffic_secret = &aes_128_secp256r1_mlkem768_client_secret,
        .expected_server_traffic_secret = &aes_128_secp256r1_mlkem768_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_secp256r1_mlkem768_client_secret, AES_256_SECP256R1_MLKEM768_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_secp256r1_mlkem768_server_secret, AES_256_SECP256R1_MLKEM768_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_secp256r1_mlkem768_vector = {
        .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_secp256r1_mlkem_768,
        .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
        .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
        .pq_secret = &mlkem768_secret,
        .expected_hybrid_secret = &secp256r1_mlkem768_hybrid_secret,
        .expected_client_traffic_secret = &aes_256_secp256r1_mlkem768_client_secret,
        .expected_server_traffic_secret = &aes_256_secp256r1_mlkem768_server_secret,
    };

    S2N_BLOB_FROM_HEX(mlkem1024_secret, MLKEM1024_SECRET);
    S2N_BLOB_FROM_HEX(secp384r1_mlkem1024_hybrid_secret, SECP384R1_MLKEM1024_HYBRID_SECRET);

    S2N_BLOB_FROM_HEX(aes_128_secp384r1_mlkem1024_client_secret, AES_128_SECP384R1_MLKEM1024_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp384r1_mlkem1024_server_secret, AES_128_SECP384R1_MLKEM1024_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_secp384r1_mlkem1024_vector = {
        .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_secp384r1_mlkem_1024,
        .client_ecc_key = CLIENT_SECP384R1_PRIV_KEY,
        .server_ecc_key = SERVER_SECP384R1_PRIV_KEY,
        .pq_secret = &mlkem1024_secret,
        .expected_hybrid_secret = &secp384r1_mlkem1024_hybrid_secret,
        .expected_client_traffic_secret = &aes_128_secp384r1_mlkem1024_client_secret,
        .expected_server_traffic_secret = &aes_128_secp384r1_mlkem1024_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_secp384r1_mlkem1024_client_secret, AES_256_SECP384R1_MLKEM1024_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_secp384r1_mlkem1024_server_secret, AES_256_SECP384R1_MLKEM1024_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_secp384r1_mlkem1024_vector = {
        .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_secp384r1_mlkem_1024,
        .client_ecc_key = CLIENT_SECP384R1_PRIV_KEY,
        .server_ecc_key = SERVER_SECP384R1_PRIV_KEY,
        .pq_secret = &mlkem1024_secret,
        .expected_hybrid_secret = &secp384r1_mlkem1024_hybrid_secret,
        .expected_client_traffic_secret = &aes_256_secp384r1_mlkem1024_client_secret,
        .expected_server_traffic_secret = &aes_256_secp384r1_mlkem1024_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_128_x25519_mlkem768_client_secret, AES_128_X25519_MLKEM768_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_mlkem768_server_secret, AES_128_X25519_MLKEM768_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_x25519_mlkem768_vector = {
        .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_x25519_mlkem_768,
        .client_ecc_key = CLIENT_X25519_PRIV_KEY,
        .server_ecc_key = SERVER_X25519_PRIV_KEY,
        .pq_secret = &mlkem768_secret,
        .expected_hybrid_secret = &x25519_mlkem768_hybrid_secret,
        .expected_client_traffic_secret = &aes_128_x25519_mlkem768_client_secret,
        .expected_server_traffic_secret = &aes_128_x25519_mlkem768_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_x25519_mlkem768_client_secret, AES_256_X25519_MLKEM768_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_x25519_mlkem768_server_secret, AES_256_X25519_MLKEM768_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_x25519_mlkem768_vector = {
        .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
        .transcript = FAKE_TRANSCRIPT,
        .kem_group = &s2n_x25519_mlkem_768,
        .client_ecc_key = CLIENT_X25519_PRIV_KEY,
        .server_ecc_key = SERVER_X25519_PRIV_KEY,
        .pq_secret = &mlkem768_secret,
        .expected_hybrid_secret = &x25519_mlkem768_hybrid_secret,
        .expected_client_traffic_secret = &aes_256_x25519_mlkem768_client_secret,
        .expected_server_traffic_secret = &aes_256_x25519_mlkem768_server_secret,
    };

    const struct hybrid_test_vector *all_test_vectors[] = {
        &aes_128_sha_256_secp256r1_mlkem768_vector,
        &aes_256_sha_384_secp256r1_mlkem768_vector,
        &aes_128_sha_256_secp384r1_mlkem1024_vector,
        &aes_256_sha_384_secp384r1_mlkem1024_vector,
        &aes_128_sha_256_x25519_mlkem768_vector,
        &aes_256_sha_384_x25519_mlkem768_vector,
    };

    EXPECT_EQUAL(s2n_array_len(all_test_vectors), (2 * S2N_HYBRID_KEM_GROUPS_COUNT));

    {
        /* Happy cases for computing the hybrid shared secret and client & server traffic secrets */
        for (int i = 0; i < s2n_array_len(all_test_vectors); i++) {
            const struct hybrid_test_vector *test_vector = all_test_vectors[i];
            const struct s2n_kem_group *kem_group = test_vector->kem_group;
            /* Skip |kem_group| if unavailable due to lack of curve support. */
            if (!s2n_kem_group_is_available(kem_group) && kem_group->curve->name == NULL) {
                continue;
            }

            /* Set up connections */
            struct s2n_connection *client_conn = NULL;
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            /* Expect success here regardless of whether a given kem_group is
             * available because we will fall back to ECDH if no KEM groups are
             * available. */
            EXPECT_SUCCESS(set_up_conns(client_conn, server_conn, test_vector->client_ecc_key,
                    test_vector->server_ecc_key, kem_group, test_vector->pq_secret));

            /* Calculate the hybrid shared secret */
            DEFER_CLEANUP(struct s2n_blob client_calculated_shared_secret = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob server_calculated_shared_secret = { 0 }, s2n_free);
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
    };
    {
        /* Various failure cases for s2n_tls13_compute_shared_secret() */
        const struct hybrid_test_vector *test_vector = &aes_128_sha_256_x25519_mlkem768_vector;
        s2n_mode modes[] = { S2N_SERVER, S2N_CLIENT };

        for (size_t i = 0; i < s2n_array_len(modes); i++) {
            if (!s2n_kem_group_is_available(test_vector->kem_group)) {
                continue;
            }
            /* Failures because of NULL arguments */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(NULL, NULL), S2N_ERR_NULL);
            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(modes[i]));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, NULL), S2N_ERR_NULL);
            DEFER_CLEANUP(struct s2n_blob calculated_shared_secret = { 0 }, s2n_free);
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(NULL, &calculated_shared_secret), S2N_ERR_NULL);

            /* Failures because classic (non-hybrid) parameters were configured */
            conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_SAFETY);
            conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;
            EXPECT_SUCCESS(read_priv_ecc(&conn->kex_params.server_ecc_evp_params.evp_pkey, test_vector->client_ecc_key));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_SAFETY);
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&conn->kex_params.server_ecc_evp_params));

            /* Failure because the chosen_client_kem_group_params is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);

            /* Failures because the kem_group_params aren't set */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve = test_vector->kem_group->curve;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = test_vector->kem_group->curve;

            /* Failures because the ECC private keys are NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(read_priv_ecc(&conn->kex_params.client_kem_group_params.ecc_params.evp_pkey, test_vector->client_ecc_key));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(read_priv_ecc(&conn->kex_params.server_kem_group_params.ecc_params.evp_pkey, test_vector->server_ecc_key));

            /* Failure because pq_shared_secret is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(s2n_dup(test_vector->pq_secret, &conn->kex_params.client_kem_group_params.kem_params.shared_secret));

            /* Failure because the kem_group is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->kex_params.server_kem_group_params.kem_group = test_vector->kem_group;

            /* Finally, success */
            EXPECT_SUCCESS(s2n_tls13_compute_pq_shared_secret(conn, &calculated_shared_secret));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    END_TEST();
}

static int read_priv_ecc(EVP_PKEY **pkey, const char *priv_ecc)
{
    size_t key_len = sizeof(char) * strlen(priv_ecc);

#if defined(LIBRESSL_VERSION_NUMBER)
    /* LibreSSL's BIO_new_mem_buf() function signature requires a non-const
     * input buffer. */

    DEFER_CLEANUP(struct s2n_blob priv_ecc_blob = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&priv_ecc_blob, key_len));
    for (size_t i = 0; i < key_len; i++) {
        priv_ecc_blob.data[i] = priv_ecc[i];
    }

    BIO *bio = BIO_new_mem_buf((void *) priv_ecc_blob.data, key_len);
#else
    BIO *bio = BIO_new_mem_buf((const void *) priv_ecc, key_len);
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
        struct s2n_blob *pq_shared_secret)
{
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
    struct s2n_stuffer private_key_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&private_key_stuffer,
            &client_conn->kex_params.client_kem_group_params.kem_params.private_key));
    uint8_t fake_private_key[] = { 3, 3 };
    POSIX_GUARD(s2n_stuffer_write_bytes(&private_key_stuffer, fake_private_key, 2));

    /* "Import" the provided private ECC keys */
    POSIX_ENSURE_EQ(sizeof(char) * strlen(client_priv_ecc), sizeof(char) * strlen(server_priv_ecc));
    POSIX_GUARD(read_priv_ecc(&client_conn->kex_params.client_kem_group_params.ecc_params.evp_pkey, client_priv_ecc));
    POSIX_ENSURE_REF(client_conn->kex_params.client_kem_group_params.ecc_params.evp_pkey);
    POSIX_GUARD(read_priv_ecc(&server_conn->kex_params.server_kem_group_params.ecc_params.evp_pkey, server_priv_ecc));
    POSIX_ENSURE_REF(server_conn->kex_params.server_kem_group_params.ecc_params.evp_pkey);

    /* Each peer sends its public ECC key to the other */
    struct s2n_stuffer wire = { 0 };
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

static int assert_kem_group_params_freed(struct s2n_connection *conn)
{
    POSIX_ENSURE_EQ(NULL, conn->kex_params.server_kem_group_params.ecc_params.evp_pkey);
    POSIX_ENSURE_EQ(NULL, conn->kex_params.server_kem_group_params.kem_params.shared_secret.data);
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
