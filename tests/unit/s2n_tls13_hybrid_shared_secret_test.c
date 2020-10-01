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

#if !defined(S2N_NO_PQ)

static int read_priv_ecc(EVP_PKEY **pkey, const char *priv_ecc);
static int set_up_conns(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
                        const char *client_priv_ecc, const char *server_priv_ecc, const struct s2n_kem_group *kem_group,
                        struct s2n_blob *pq_shared_secret);
static int assert_kem_group_params_freed(struct s2n_connection *conn);

struct hybrid_test_vector {
    const struct s2n_kem_group *kem_group;
    const struct s2n_cipher_suite *cipher_suite;
    const char *transcript;
    const char *client_ecc_key;
    const char *server_ecc_key;
    struct s2n_blob *pq_secret;
    struct s2n_blob *expected_hybrid_secret;
    struct s2n_blob *expected_client_traffic_secret;
    struct s2n_blob *expected_server_traffic_secret;
};

#endif

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
#define SIKEP434R2_SECRET "35f7f8ff388714dedc41f139078cedc9"
#define BIKE1L1R2_SECRET "C1C96E2B8B1D23E52F02AD3A766A75ADBEDF7BA1558B94412B4AB534EEDBDE36"
#define KYBER512R2_SECRET "D0FF6083EE6E516C10AECB53DB05426C382A1A75F3E943C9F469A060C634EF4E"

/* Hybrid shared secrets are the concatenation: ECDHE || PQ */
#define X25519_SIKEP434R2_HYBRID_SECRET      (X25519_SHARED_SECRET      SIKEP434R2_SECRET)
#define SECP256R1_SIKEP434R2_HYBRID_SECRET   (SECP256R1_SHARED_SECRET   SIKEP434R2_SECRET)
#define X25519_BIKE1L1R2_HYBRID_SECRET       (X25519_SHARED_SECRET      BIKE1L1R2_SECRET)
#define SECP256R1_BIKE1L1R2_HYBRID_SECRET    (SECP256R1_SHARED_SECRET   BIKE1L1R2_SECRET)
#define X25519_KYBER512R2_HYBRID_SECRET      (X25519_SHARED_SECRET      KYBER512R2_SECRET)
#define SECP256R1_KYBER512R2_HYBRID_SECRET   (SECP256R1_SHARED_SECRET   KYBER512R2_SECRET)

/* The expected traffic secrets were calculated from an independent implementation,
 * using the ECDHE & PQ secrets defined above. */
#define AES_128_SECP256R1_SIKEP434R2_CLIENT_TRAFFIC_SECRET "2fa1a075eaf636138170e3b2a84f6baa4ac08f846ffe2d005ae5e66b03352c11"
#define AES_128_SECP256R1_SIKEP434R2_SERVER_TRAFFIC_SECRET "423dfaf8fd66b17aaf8c919a9318f3a6bd69875aacdf022aa58a953a7b6de806"
#define AES_256_SECP256R1_SIKEP434R2_CLIENT_TRAFFIC_SECRET "f7d349f364f49ff3ae9c4e9e7aa60c41d6c650d09c03d8c076bc714ab76177045e23e7426dceb872d2fe7c0d07abdefd"
#define AES_256_SECP256R1_SIKEP434R2_SERVER_TRAFFIC_SECRET "184755801232f7b9b5c42cbdc66c793071f4322079e34307fd60261c0f7a27612b3808918218c4000c12f829d6c19ebf"

#define AES_128_X25519_SIKEP434_CLIENT_TRAFFIC_SECRET "9b9c53221edb5cc1f95ab2ecfc5eb8ec27d6b9fc2159c956333cd90099911dc7"
#define AES_128_X25519_SIKEP434_SERVER_TRAFFIC_SECRET "29a8786ffc6a48692b95d70ab7e04bcf112afd0a019dff6c15c1d095cfa5ebcc"
#define AES_256_X25519_SIKEP434_CLIENT_TRAFFIC_SECRET "c7ee90f95fdfd53d97da07e338c7b6aa9e5111864d66d9631048941f45c9fd1a7b119871594140000923a79333040775"
#define AES_256_X25519_SIKEP434_SERVER_TRAFFIC_SECRET "aff2987e4ed3c2bc55cbd9e3e52db0cc330034dfa709e0a4127c4d74278198720b74a444afa8f0f7dca115797470cef2"

#define AES_128_SECP256R1_BIKE1L1R2_CLIENT_TRAFFIC_SECRET "67ed1aec6227ce924087b4a2224ec697ae164dc8541eee3c3d393dda2bd10958"
#define AES_128_SECP256R1_BIKE1L1R2_SERVER_TRAFFIC_SECRET "c0d1cf356e224db5fa693b91bad93130915448913fd3509257188a3f064585d1"
#define AES_256_SECP256R1_BIKE1L1R2_CLIENT_TRAFFIC_SECRET "fd5d731c6454c523dd029a2311346da9969c30ea8cead8a6e19f211762c2bbabd182e6fb599527b26eecf86f3329103c"
#define AES_256_SECP256R1_BIKE1L1R2_SERVER_TRAFFIC_SECRET "03dcd83c4ae4cd4dd5a76404afd3147e277a748ec3f10e8c1427ae37c1c0cc0eff29149cb14b61da49696510dc0182d2"

#define AES_128_X25519_BIKE1L1R2_CLIENT_TRAFFIC_SECRET "3a0d971f4461ee69688eb1159c1640d429e2255473f2e2668b1cbab4ac80a47f"
#define AES_128_X25519_BIKE1L1R2_SERVER_TRAFFIC_SECRET "74ea914ef6416dbe16b75a568c00d505c66770b0938539fccbfe3051460ab583"
#define AES_256_X25519_BIKE1L1R2_CLIENT_TRAFFIC_SECRET "982ea3ccdd83225b6b2bb8a2f623e4f9b9cdcca1f5a11ea2b94f264bbf6785d6c1db3232ceb395eb79ddcae3f754fe7d"
#define AES_256_X25519_BIKE1L1R2_SERVER_TRAFFIC_SECRET "510970206a3eb187c8ea4ad5f91b738e44dee08616579a16572320e2dac46f6dfa5d072c0f5ac08b9e3480b28d6d8923"

#define AES_128_SECP256R1_KYBER512R2_CLIENT_TRAFFIC_SECRET "e0f4482f8d26a9e4ebdfe18e863c5c8bd53ac0be32b592981eff121f8b35c772"
#define AES_128_SECP256R1_KYBER512R2_SERVER_TRAFFIC_SECRET "0835f1a49664b648bab6388494d72349a87e18cfef2cc7d5e2885204997c8ef7"
#define AES_256_SECP256R1_KYBER512R2_CLIENT_TRAFFIC_SECRET "23c1e662bcc30a3cbafd440fbd3bdcf527b538ca4bce09dfb2e7e7b13242051be1a51b725c38d4116fe9039166d1ee18"
#define AES_256_SECP256R1_KYBER512R2_SERVER_TRAFFIC_SECRET "81e996d8a50d61a86894a8ee776e65dbe6da766debf27b53244eb14938f3904736ef422512a57cad86e6ec731e34e0b0"

#define AES_128_X25519_KYBER512R2_CLIENT_TRAFFIC_SECRET "8e86d7e648d661cd18fa752caac6175e8e5bd6d7c459c091af0558a94b8d9f9d"
#define AES_128_X25519_KYBER512R2_SERVER_TRAFFIC_SECRET "b186dfdb8fcb91f6bb888e55a73f4afa03e86bab7cc81f6a8ae589bffa9926ed"
#define AES_256_X25519_KYBER512R2_CLIENT_TRAFFIC_SECRET "d30b4e9ab4416e10fa6e3ed2d2bfde3eecaa1e3d9e75b95b035a9d8a3b240c5e483dee0ebd01fd26bec3662b18cd92e2"
#define AES_256_X25519_KYBER512R2_SERVER_TRAFFIC_SECRET "ad980d9998e7899e214ae30859125283202a27c96eed23f4dba9991b99785cef79ad1e9dacb1e3017262c476b91c82ff"

/* A fake transcript string to hash when deriving handshake secrets */
#define FAKE_TRANSCRIPT "client_hello || server_hello"

int main(int argc, char **argv) {
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }

    S2N_BLOB_FROM_HEX(sikep434r2_secret, SIKEP434R2_SECRET);

    S2N_BLOB_FROM_HEX(secp256r1_secret, SECP256R1_SHARED_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_sikep434r2_hybrid_secret, SECP256R1_SIKEP434R2_HYBRID_SECRET);

    S2N_BLOB_FROM_HEX(aes_128_secp256r1_sikep434r2_client_secret, AES_128_SECP256R1_SIKEP434R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_sikep434r2_server_secret, AES_128_SECP256R1_SIKEP434R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_secp256r1_sikep434r2_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_sike_p434_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &sikep434r2_secret,
            .expected_hybrid_secret = &secp256r1_sikep434r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_secp256r1_sikep434r2_client_secret,
            .expected_server_traffic_secret = &aes_128_secp256r1_sikep434r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_secp256r1_sikep434r2_client_secret, AES_256_SECP256R1_SIKEP434R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_secp256r1_sikep434r2_server_secret, AES_256_SECP256R1_SIKEP434R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_secp256r1_sikep434r2_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_sike_p434_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &sikep434r2_secret,
            .expected_hybrid_secret = &secp256r1_sikep434r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_secp256r1_sikep434r2_client_secret,
            .expected_server_traffic_secret = &aes_256_secp256r1_sikep434r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(bike1l1r2_secret, BIKE1L1R2_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_bike1l1r2_hybrid_secret, SECP256R1_BIKE1L1R2_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_bike1l1r2_client_secret, AES_128_SECP256R1_BIKE1L1R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_bike1l1r2_server_secret, AES_128_SECP256R1_BIKE1L1R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_secp256r1_bike1l1r2_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_bike1_l1_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &bike1l1r2_secret,
            .expected_hybrid_secret = &secp256r1_bike1l1r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_secp256r1_bike1l1r2_client_secret,
            .expected_server_traffic_secret = &aes_128_secp256r1_bike1l1r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_secp256r1_bike1l1r2_client_secret, AES_256_SECP256R1_BIKE1L1R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_secp256r1_bike1l1r2_server_secret, AES_256_SECP256R1_BIKE1L1R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_secp256r1_bike1l1r2_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_bike1_l1_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &bike1l1r2_secret,
            .expected_hybrid_secret = &secp256r1_bike1l1r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_secp256r1_bike1l1r2_client_secret,
            .expected_server_traffic_secret = &aes_256_secp256r1_bike1l1r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(kyber512r2_secret, KYBER512R2_SECRET);
    S2N_BLOB_FROM_HEX(secp256r1_kyber512r2_hybrid_secret, SECP256R1_KYBER512R2_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_kyber512r2_client_secret, AES_128_SECP256R1_KYBER512R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_secp256r1_kyber512r2_server_secret, AES_128_SECP256R1_KYBER512R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_secp256r1_kyber512r2_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_kyber_512_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &kyber512r2_secret,
            .expected_hybrid_secret = &secp256r1_kyber512r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_secp256r1_kyber512r2_client_secret,
            .expected_server_traffic_secret = &aes_128_secp256r1_kyber512r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_secp256r1_kyber512r2_client_secret, AES_256_SECP256R1_KYBER512R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_secp256r1_kyber512r2_server_secret, AES_256_SECP256R1_KYBER512R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_secp256r1_kyber512r2_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_secp256r1_kyber_512_r2,
            .client_ecc_key = CLIENT_SECP256R1_PRIV_KEY,
            .server_ecc_key = SERVER_SECP256R1_PRIV_KEY,
            .pq_secret = &kyber512r2_secret,
            .expected_hybrid_secret = &secp256r1_kyber512r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_secp256r1_kyber512r2_client_secret,
            .expected_server_traffic_secret = &aes_256_secp256r1_kyber512r2_server_secret,
    };

#if EVP_APIS_SUPPORTED
    /* All x25519 based tls13_kem_groups require EVP_APIS_SUPPORTED */
    S2N_BLOB_FROM_HEX(x25519_secret, X25519_SHARED_SECRET);
    S2N_BLOB_FROM_HEX(x25519_sikep434r2_hybrid_secret, X25519_SIKEP434R2_HYBRID_SECRET);

    S2N_BLOB_FROM_HEX(aes_128_x25519_sikep434r2_client_secret, AES_128_X25519_SIKEP434_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_sikep434r2_server_secret, AES_128_X25519_SIKEP434_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_x25519_sikep434r2_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_sike_p434_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &sikep434r2_secret,
            .expected_hybrid_secret = &x25519_sikep434r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_x25519_sikep434r2_client_secret,
            .expected_server_traffic_secret = &aes_128_x25519_sikep434r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_x25519_sikep434r2_client_secret, AES_256_X25519_SIKEP434_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_x25519_sikep434r2_server_secret, AES_256_X25519_SIKEP434_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_x25519_sikep434r2_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_sike_p434_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &sikep434r2_secret,
            .expected_hybrid_secret = &x25519_sikep434r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_x25519_sikep434r2_client_secret,
            .expected_server_traffic_secret = &aes_256_x25519_sikep434r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(x25519_bike1l1r2_hybrid_secret, X25519_BIKE1L1R2_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_bike1l1r2_client_secret, AES_128_X25519_BIKE1L1R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_bike1l1r2_server_secret, AES_128_X25519_BIKE1L1R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_x25519_bike1l1r2_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_bike1_l1_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &bike1l1r2_secret,
            .expected_hybrid_secret = &x25519_bike1l1r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_x25519_bike1l1r2_client_secret,
            .expected_server_traffic_secret = &aes_128_x25519_bike1l1r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_x25519_bike1l1r2_client_secret, AES_256_X25519_BIKE1L1R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_x25519_bike1l1r2_server_secret, AES_256_X25519_BIKE1L1R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_x25519_bike1l1r2_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_bike1_l1_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &bike1l1r2_secret,
            .expected_hybrid_secret = &x25519_bike1l1r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_x25519_bike1l1r2_client_secret,
            .expected_server_traffic_secret = &aes_256_x25519_bike1l1r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(x25519_kyber512r2_hybrid_secret, X25519_KYBER512R2_HYBRID_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_kyber512r2_client_secret, AES_128_X25519_KYBER512R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_128_x25519_kyber512r2_server_secret, AES_128_X25519_KYBER512R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_128_sha_256_x25519_kyber512r2_vector = {
            .cipher_suite = &s2n_tls13_aes_128_gcm_sha256,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_kyber_512_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &kyber512r2_secret,
            .expected_hybrid_secret = &x25519_kyber512r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_128_x25519_kyber512r2_client_secret,
            .expected_server_traffic_secret = &aes_128_x25519_kyber512r2_server_secret,
    };

    S2N_BLOB_FROM_HEX(aes_256_x25519_kyber512r2_client_secret, AES_256_X25519_KYBER512R2_CLIENT_TRAFFIC_SECRET);
    S2N_BLOB_FROM_HEX(aes_256_x25519_kyber512r2_server_secret, AES_256_X25519_KYBER512R2_SERVER_TRAFFIC_SECRET);

    const struct hybrid_test_vector aes_256_sha_384_x25519_kyber512r2_vector = {
            .cipher_suite = &s2n_tls13_aes_256_gcm_sha384,
            .transcript = FAKE_TRANSCRIPT,
            .kem_group = &s2n_x25519_kyber_512_r2,
            .client_ecc_key = CLIENT_X25519_PRIV_KEY,
            .server_ecc_key = SERVER_X25519_PRIV_KEY,
            .pq_secret = &kyber512r2_secret,
            .expected_hybrid_secret = &x25519_kyber512r2_hybrid_secret,
            .expected_client_traffic_secret = &aes_256_x25519_kyber512r2_client_secret,
            .expected_server_traffic_secret = &aes_256_x25519_kyber512r2_server_secret,
    };
#endif

#if EVP_APIS_SUPPORTED
    EXPECT_EQUAL(6, S2N_SUPPORTED_KEM_GROUPS_COUNT);
    const struct hybrid_test_vector *all_test_vectors[] = {
            &aes_128_sha_256_secp256r1_sikep434r2_vector,
            &aes_256_sha_384_secp256r1_sikep434r2_vector,
            &aes_128_sha_256_x25519_sikep434r2_vector,
            &aes_256_sha_384_x25519_sikep434r2_vector,
            &aes_128_sha_256_secp256r1_bike1l1r2_vector,
            &aes_256_sha_384_secp256r1_bike1l1r2_vector,
            &aes_128_sha_256_x25519_bike1l1r2_vector,
            &aes_256_sha_384_x25519_bike1l1r2_vector,
            &aes_128_sha_256_secp256r1_kyber512r2_vector,
            &aes_256_sha_384_secp256r1_kyber512r2_vector,
            &aes_128_sha_256_x25519_kyber512r2_vector,
            &aes_256_sha_384_x25519_kyber512r2_vector,
    };
#else
    EXPECT_EQUAL(3, S2N_SUPPORTED_KEM_GROUPS_COUNT);
    const struct hybrid_test_vector *all_test_vectors[] = {
            &aes_128_sha_256_secp256r1_sikep434r2_vector,
            &aes_256_sha_384_secp256r1_sikep434r2_vector,
            &aes_128_sha_256_secp256r1_bike1l1r2_vector,
            &aes_256_sha_384_secp256r1_bike1l1r2_vector,
            &aes_128_sha_256_secp256r1_kyber512r2_vector,
            &aes_256_sha_384_secp256r1_kyber512r2_vector,
    };
#endif

    EXPECT_EQUAL(2 * S2N_SUPPORTED_KEM_GROUPS_COUNT, s2n_array_len(all_test_vectors));

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

            /* Compute the transcript hash, then use the hybrid shared secret to derive
             * the client & server traffic secrets */
            DEFER_CLEANUP(struct s2n_tls13_keys secrets = {0}, s2n_tls13_keys_free);
            EXPECT_SUCCESS(s2n_tls13_keys_init(&secrets, test_vector->cipher_suite->prf_alg));
            EXPECT_SUCCESS(s2n_tls13_derive_early_secrets(&secrets));

            DEFER_CLEANUP(struct s2n_hash_state hash_state, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&hash_state));
            EXPECT_SUCCESS(s2n_hash_init(&hash_state, secrets.hash_algorithm));
            EXPECT_SUCCESS(s2n_hash_update(&hash_state, test_vector->transcript, strlen(test_vector->transcript)));

            s2n_tls13_key_blob(client_traffic_secret, secrets.size);
            s2n_tls13_key_blob(server_traffic_secret, secrets.size);

            EXPECT_SUCCESS(s2n_tls13_derive_handshake_secrets(&secrets, &client_calculated_shared_secret,
                    &hash_state, &client_traffic_secret, &server_traffic_secret));

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
        const struct hybrid_test_vector *test_vector = &aes_128_sha_256_secp256r1_sikep434r2_vector;
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
            conn->secure.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_SAFETY);
            conn->secure.server_ecc_evp_params.negotiated_curve = NULL;
            EXPECT_SUCCESS(read_priv_ecc(&conn->secure.server_ecc_evp_params.evp_pkey, test_vector->client_ecc_key));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_SAFETY);
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&conn->secure.server_ecc_evp_params));

            /* Failure because the chosen_client_kem_group_params is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->secure.chosen_client_kem_group_params = &conn->secure.client_kem_group_params[0];

            /* Failures because the kem_group_params aren't set */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->secure.server_kem_group_params.ecc_params.negotiated_curve = test_vector->kem_group->curve;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->secure.chosen_client_kem_group_params->ecc_params.negotiated_curve = test_vector->kem_group->curve;

            /* Failures because the ECC private keys are NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(read_priv_ecc(&conn->secure.chosen_client_kem_group_params->ecc_params.evp_pkey, test_vector->client_ecc_key));
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(read_priv_ecc(&conn->secure.server_kem_group_params.ecc_params.evp_pkey, test_vector->server_ecc_key));

            /* Failure because pq_shared_secret is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            EXPECT_SUCCESS(s2n_dup(test_vector->pq_secret, &conn->secure.chosen_client_kem_group_params->kem_params.shared_secret));

            /* Failure because the kem_group is NULL */
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret), S2N_ERR_NULL);
            conn->secure.server_kem_group_params.kem_group = test_vector->kem_group;

            /* Finally, success */
            EXPECT_SUCCESS(s2n_tls13_compute_pq_hybrid_shared_secret(conn, &calculated_shared_secret));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

#endif

    END_TEST();
}

#if !defined(S2N_NO_PQ)

static int read_priv_ecc(EVP_PKEY **pkey, const char *priv_ecc) {
    size_t key_len = sizeof(char) * strlen(priv_ecc);

#if defined(LIBRESSL_VERSION_NUMBER)
    /* LibreSSL's BIO_new_mem_buf() function signature requires a non-const
     * input buffer. */

    DEFER_CLEANUP(struct s2n_blob priv_ecc_blob = { 0 }, s2n_free);
    GUARD(s2n_alloc(&priv_ecc_blob, key_len));
    for (size_t i = 0; i < key_len; i++) {
        priv_ecc_blob.data[i] = priv_ecc[i];
    }

    BIO *bio = BIO_new_mem_buf((void *)priv_ecc_blob.data, key_len);
#else
    BIO *bio = BIO_new_mem_buf((const void *)priv_ecc, key_len);
#endif

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

    /* During an actual handshake, server will generate the shared secret and store it in chosen_client_kem_group_params,
     * client will decapsulate the ciphertext and store the shared secret in chosen_client_kem_group_params. */
    GUARD(s2n_dup(pq_shared_secret, &server_conn->secure.chosen_client_kem_group_params->kem_params.shared_secret));
    GUARD(s2n_dup(pq_shared_secret, &client_conn->secure.chosen_client_kem_group_params->kem_params.shared_secret));

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

#endif
