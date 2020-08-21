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
#include "tests/s2n_test.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/extensions/s2n_key_share.h"

#include "utils/s2n_safety.h"

#include "crypto/s2n_fips.h"
#include "crypto/s2n_ecc_evp.h"

#define TEST_PUBLIC_KEY_LENGTH 2
const uint8_t TEST_PUBLIC_KEY[] = { 2, 2 };
#define TEST_PRIVATE_KEY_LENGTH 3
const uint8_t TEST_PRIVATE_KEY[] = { 3, 3, 3 };
#define TEST_SHARED_SECRET_LENGTH 4
const uint8_t TEST_SHARED_SECRET[] = { 4, 4, 4, 4 };
#define TEST_CIPHERTEXT_LENGTH 5
const uint8_t TEST_CIPHERTEXT[] = { 5, 5, 5, 5, 5 };

#if !defined(S2N_NO_PQ)

static const uint8_t kyber_iana[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 };
static const uint8_t bike_iana[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384 };
static const uint8_t sike_iana[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 };
static const uint8_t classic_ecdhe_iana[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA };

int alloc_test_kem_params(struct s2n_kem_params *kem_params) {
    GUARD(s2n_alloc(&(kem_params->private_key), TEST_PRIVATE_KEY_LENGTH));
    struct s2n_stuffer private_key_stuffer = {0};
    GUARD(s2n_stuffer_init(&private_key_stuffer, &(kem_params->private_key)));
    GUARD(s2n_stuffer_write_bytes(&private_key_stuffer, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH));

    GUARD(s2n_alloc(&(kem_params->public_key), TEST_PUBLIC_KEY_LENGTH));
    struct s2n_stuffer public_key_stuffer = {0};
    GUARD(s2n_stuffer_init(&public_key_stuffer, &(kem_params->public_key)));
    GUARD(s2n_stuffer_write_bytes(&public_key_stuffer, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH));

    GUARD(s2n_alloc(&(kem_params->shared_secret), TEST_SHARED_SECRET_LENGTH));
    struct s2n_stuffer shared_secret_stuffer = {0};
    GUARD(s2n_stuffer_init(&shared_secret_stuffer, &(kem_params->shared_secret)));
    GUARD(s2n_stuffer_write_bytes(&shared_secret_stuffer, TEST_SHARED_SECRET, TEST_SHARED_SECRET_LENGTH));

    ne_check(0, kem_params->private_key.allocated);
    ne_check(0, kem_params->public_key.allocated);
    ne_check(0, kem_params->shared_secret.allocated);

    return S2N_SUCCESS;
}

int assert_kem_params_free(struct s2n_kem_params *kem_params) {
    eq_check(NULL, kem_params->private_key.data);
    eq_check(0, kem_params->private_key.size);
    eq_check(0, kem_params->private_key.allocated);

    eq_check(NULL, kem_params->public_key.data);
    eq_check(0, kem_params->public_key.size);
    eq_check(0, kem_params->public_key.allocated);

    eq_check(NULL, kem_params->shared_secret.data);
    eq_check(0, kem_params->shared_secret.size);
    eq_check(0, kem_params->shared_secret.allocated);

    return S2N_SUCCESS;
}

int s2n_test_generate_keypair(unsigned char *public_key, unsigned char *private_key)
{
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);
    memset(public_key, TEST_PUBLIC_KEY_LENGTH, TEST_PUBLIC_KEY_LENGTH);
    memset(private_key, TEST_PRIVATE_KEY_LENGTH, TEST_PRIVATE_KEY_LENGTH);
    return 0;
}
int s2n_test_encrypt(unsigned char *ciphertext, unsigned char *shared_secret, const unsigned char *public_key)
{
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);
    GUARD(memcmp(public_key, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH));
    memset(ciphertext, TEST_CIPHERTEXT_LENGTH, TEST_CIPHERTEXT_LENGTH);
    memset(shared_secret, TEST_SHARED_SECRET_LENGTH, TEST_SHARED_SECRET_LENGTH);
    return 0;
}
int s2n_test_decrypt(unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key)
{
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);
    GUARD(memcmp(ciphertext, TEST_CIPHERTEXT, TEST_CIPHERTEXT_LENGTH));
    GUARD(memcmp(private_key, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH));
    memset(shared_secret, TEST_SHARED_SECRET_LENGTH, TEST_SHARED_SECRET_LENGTH);
    return 0;
}

const struct s2n_kem s2n_test_kem = {
    .public_key_length = TEST_PUBLIC_KEY_LENGTH,
    .private_key_length = TEST_PRIVATE_KEY_LENGTH,
    .shared_secret_key_length = TEST_SHARED_SECRET_LENGTH,
    .ciphertext_length = TEST_CIPHERTEXT_LENGTH,
    .generate_keypair = &s2n_test_generate_keypair,
    .encapsulate = &s2n_test_encrypt,
    .decapsulate = &s2n_test_decrypt,
};

static int check_client_server_agreed_kem(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], uint8_t *client_kem_ids, const uint8_t num_client_kems,
        const struct s2n_kem *server_kem_pref_list[], const uint8_t num_server_supported_kems, kem_extension_size expected_kem_id) {
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    const struct s2n_kem *negotiated_kem = NULL;
    struct s2n_blob client_kem_blob = { 0 };
    /* Each KEM ID is 2 bytes */
    GUARD(s2n_blob_init(&client_kem_blob, client_kem_ids, 2 * num_client_kems));
    GUARD(s2n_choose_kem_with_peer_pref_list(iana_value, &client_kem_blob, server_kem_pref_list, num_server_supported_kems, &negotiated_kem));
    GUARD_NONNULL(negotiated_kem);

    S2N_ERROR_IF(negotiated_kem->kem_extension_id != expected_kem_id, S2N_ERR_KEM_UNSUPPORTED_PARAMS);

    return 0;
}

#endif

int main(int argc, char **argv)
{
    BEGIN_TEST();
    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }

#if !defined(S2N_NO_PQ)

    {
        /* Regression test for network parsing data of expected sizes */
        EXPECT_EQUAL(sizeof(kem_extension_size), 2);
        EXPECT_EQUAL(sizeof(kem_public_key_size), 2);
        EXPECT_EQUAL(sizeof(kem_private_key_size), 2);
        EXPECT_EQUAL(sizeof(kem_shared_secret_size), 2);
        EXPECT_EQUAL(sizeof(kem_ciphertext_key_size), 2);
    }
    {
        struct s2n_kem_params server_kem_params = { 0 };
        server_kem_params.kem = &s2n_test_kem;
        EXPECT_SUCCESS(s2n_alloc(&server_kem_params.public_key, TEST_PUBLIC_KEY_LENGTH));
        EXPECT_SUCCESS(s2n_kem_generate_keypair(&server_kem_params));
        EXPECT_EQUAL(TEST_PUBLIC_KEY_LENGTH, server_kem_params.public_key.size);
        EXPECT_EQUAL(TEST_PRIVATE_KEY_LENGTH, server_kem_params.private_key.size);
        EXPECT_BYTEARRAY_EQUAL(TEST_PUBLIC_KEY, server_kem_params.public_key.data, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_BYTEARRAY_EQUAL(TEST_PRIVATE_KEY, server_kem_params.private_key.data, TEST_PRIVATE_KEY_LENGTH);
        /* KeyGen shouldn't modify the shared secret */
        EXPECT_EQUAL(0, server_kem_params.shared_secret.size);
        EXPECT_EQUAL(0, server_kem_params.shared_secret.allocated);
        EXPECT_NULL(server_kem_params.shared_secret.data);

        struct s2n_kem_params client_kem_params = { 0 };
        client_kem_params.kem = &s2n_test_kem;
        /* This would be handled by client/server key exchange methods which isn't being tested */
        GUARD(s2n_alloc(&client_kem_params.public_key, TEST_PUBLIC_KEY_LENGTH));
        memset(client_kem_params.public_key.data, TEST_PUBLIC_KEY_LENGTH, TEST_PUBLIC_KEY_LENGTH);

        DEFER_CLEANUP(struct s2n_blob ciphertext = { 0 }, s2n_free);
        GUARD(s2n_alloc(&ciphertext, TEST_CIPHERTEXT_LENGTH));

        EXPECT_SUCCESS(s2n_kem_encapsulate(&client_kem_params, &ciphertext));
        EXPECT_EQUAL(TEST_SHARED_SECRET_LENGTH, client_kem_params.shared_secret.size);
        EXPECT_EQUAL(TEST_CIPHERTEXT_LENGTH, ciphertext.size);
        EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, client_kem_params.shared_secret.data, TEST_SHARED_SECRET_LENGTH);
        EXPECT_BYTEARRAY_EQUAL(TEST_CIPHERTEXT, ciphertext.data, TEST_CIPHERTEXT_LENGTH);
        /* Encaps shouldn't modify the public or private keys */
        EXPECT_EQUAL(TEST_PUBLIC_KEY_LENGTH, client_kem_params.public_key.size);
        EXPECT_BYTEARRAY_EQUAL(TEST_PUBLIC_KEY, client_kem_params.public_key.data, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_EQUAL(0, client_kem_params.private_key.size);
        EXPECT_EQUAL(0, client_kem_params.private_key.allocated);
        EXPECT_NULL(client_kem_params.private_key.data);

        EXPECT_SUCCESS(s2n_kem_decapsulate(&server_kem_params, &ciphertext));
        EXPECT_EQUAL(TEST_SHARED_SECRET_LENGTH, server_kem_params.shared_secret.size);
        EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, server_kem_params.shared_secret.data, TEST_SHARED_SECRET_LENGTH);
        /* Decaps shouldn't modify the public or private keys */
        EXPECT_EQUAL(TEST_PUBLIC_KEY_LENGTH, server_kem_params.public_key.size);
        EXPECT_BYTEARRAY_EQUAL(TEST_PUBLIC_KEY, server_kem_params.public_key.data, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_EQUAL(TEST_PRIVATE_KEY_LENGTH, server_kem_params.private_key.size);
        EXPECT_BYTEARRAY_EQUAL(TEST_PRIVATE_KEY, server_kem_params.private_key.data, TEST_PRIVATE_KEY_LENGTH);

        EXPECT_SUCCESS(s2n_kem_free(&server_kem_params));
        EXPECT_SUCCESS(s2n_kem_free(&client_kem_params));
    }
    {
        /* The order of the client kem list should always be ignored; the server chooses based on the
         * order of the server preference list, as long as the client claims to support it. */
        {
            uint8_t client_kems[] = {
                /* BIKE1_L1_R1 */
                0x00, 0x01,
                /* BIKE1_L1_R2 */
                0x00, 0x0d,
                /* SIKE_P503_R1 */
                0x00, 0x0a,
                /* SIKE_P434_R2 */
                0x00, 0x13
            };

            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 4, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 4, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 4, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 4, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2));
        }
        {
            uint8_t client_kems[] = {
                /* SIKE_P503_R1 */
                0x00, 0x0a,
                /* BIKE1_L1_R1 */
                0x00, 0x01,
                /* SIKE_P434_R2 */
                0x00, 0x13,
                /* BIKE1_L1_R2 */
                0x00, 0x0d
            };

            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 4, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 4, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 4, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 4, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2));
        }
        {
            uint8_t client_kems[] = {
                /* SIKE_P503_R1 */
                0x00, 0x0a,
                /* BIKE1_L1_R1 */
                0x00, 0x01
            };

            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1));
        }
        {
            uint8_t client_kems[] = {
                /* BIKE1_L1_R2 */
                0x00, 0x0d,
                /* SIKE_P434_R2 */
                0x00, 0x13
            };

            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2));
            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2));
        }
        {
            uint8_t client_kems[] = {
                /* BIKE1_L1_R1 */
                0x00, 0x01,
                /* SIKE_P434_R2 */
                0x00, 0x13
            };

            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2));
        }
        {
            uint8_t client_kems[] = {
                /* BIKE1_L1_R1 */
                0x00, 0x01,
                /* BIKE1_L1_R2 */
                0x00, 0x0d
            };

            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2));
            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        }
        {
            uint8_t client_kems[] = {
                /* SIKE_P434_R2 */
                0x00, 0x13,
                /* SIKE_P503_R1 */
                0x00, 0x0a
            };

            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_FAILURE_WITH_ERRNO(check_client_server_agreed_kem(bike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r1, 2, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1));
            EXPECT_SUCCESS(check_client_server_agreed_kem(sike_iana, client_kems, 2, pq_kems_r2r1, 4, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2));
        }
        {
            /* If the client sends no KEMs, the server chooses whichever one it prefers. */
            const struct s2n_kem *negotiated_kem = NULL;
            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(bike_iana, pq_kems_r1, 2, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1);
            negotiated_kem = NULL;

            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(bike_iana, pq_kems_r2r1, 4, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2);
            negotiated_kem = NULL;

            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(bike_iana, pq_kems_r2r1_2020_07, 5, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2);
            negotiated_kem = NULL;

            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(sike_iana, pq_kems_r1, 2, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1);
            negotiated_kem = NULL;

            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(sike_iana, pq_kems_r2r1, 4, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2);
            negotiated_kem = NULL;

            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(sike_iana, pq_kems_r2r1_2020_07, 5, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2);
            negotiated_kem = NULL;

            EXPECT_SUCCESS(s2n_choose_kem_without_peer_pref_list(kyber_iana, pq_kems_r2r1_2020_07, 5, &negotiated_kem));
            EXPECT_NOT_NULL(negotiated_kem);
            EXPECT_EQUAL(negotiated_kem->kem_extension_id, TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R2);
            negotiated_kem = NULL;
        }
        {
            const struct s2n_kem *sike_only_server_pref_list[] = {
                &s2n_sike_p434_r2,
                &s2n_sike_p503_r1
            };

            const struct s2n_kem *bike_r2_only_server_pref_list[] = {
                &s2n_bike1_l1_r2
            };

            const struct s2n_kem *negotiated_kem = NULL;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_kem_without_peer_pref_list(bike_iana, sike_only_server_pref_list, 2, &negotiated_kem), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_NULL(negotiated_kem);

            negotiated_kem = NULL;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_kem_without_peer_pref_list(sike_iana, bike_r2_only_server_pref_list, 1, &negotiated_kem), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
            EXPECT_NULL(negotiated_kem);
        }
    }
    {
        const struct s2n_iana_to_kem *compatible_params = NULL;
        EXPECT_FAILURE_WITH_ERRNO(s2n_cipher_suite_to_kem(classic_ecdhe_iana, &compatible_params), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_NULL(compatible_params);

        compatible_params = NULL;
        EXPECT_SUCCESS(s2n_cipher_suite_to_kem(bike_iana, &compatible_params));
        EXPECT_NOT_NULL(compatible_params);
        EXPECT_EQUAL(compatible_params->kem_count, 2);
        EXPECT_EQUAL(compatible_params->kems[0]->kem_extension_id, s2n_bike1_l1_r1.kem_extension_id);
        EXPECT_EQUAL(compatible_params->kems[1]->kem_extension_id, s2n_bike1_l1_r2.kem_extension_id);

        compatible_params = NULL;
        EXPECT_SUCCESS(s2n_cipher_suite_to_kem(sike_iana, &compatible_params));
        EXPECT_NOT_NULL(compatible_params);
        EXPECT_EQUAL(compatible_params->kem_count, 2);
        EXPECT_EQUAL(compatible_params->kems[0]->kem_extension_id, s2n_sike_p503_r1.kem_extension_id);
        EXPECT_EQUAL(compatible_params->kems[1]->kem_extension_id, s2n_sike_p434_r2.kem_extension_id);

        compatible_params = NULL;
        EXPECT_SUCCESS(s2n_cipher_suite_to_kem(kyber_iana, &compatible_params));
        EXPECT_NOT_NULL(compatible_params);
        EXPECT_EQUAL(compatible_params->kem_count, 2);
        EXPECT_EQUAL(compatible_params->kems[0]->kem_extension_id, s2n_kyber_512_r2.kem_extension_id);
        EXPECT_EQUAL(compatible_params->kems[1]->kem_extension_id, s2n_kyber_512_90s_r2.kem_extension_id);
    }

    {
        /* Tests for s2n_kem_free() */
        EXPECT_SUCCESS(s2n_kem_free(NULL));

        struct s2n_kem_params kem_params = { 0 };
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));

        /* Fill kem_params with secrets and ensure that they have been freed */
        EXPECT_SUCCESS(alloc_test_kem_params(&kem_params));
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
        EXPECT_SUCCESS(assert_kem_params_free(&kem_params));
    }
    {
        /* Tests for s2n_kem_group_free() */
        EXPECT_SUCCESS(s2n_kem_group_free(NULL));

        struct s2n_kem_group_params kem_group_params = { 0 };
        EXPECT_SUCCESS(s2n_kem_group_free(&kem_group_params));

        /* Fill the kem_group_params with secrets */
        EXPECT_SUCCESS(alloc_test_kem_params(&kem_group_params.kem_params));
        struct s2n_stuffer wire;
        GUARD(s2n_stuffer_growable_alloc(&wire, 1024));
        kem_group_params.ecc_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        GUARD(s2n_ecdhe_parameters_send(&kem_group_params.ecc_params, &wire));
        GUARD(s2n_stuffer_free(&wire));
        EXPECT_NOT_NULL(kem_group_params.ecc_params.evp_pkey);

        /* Ensure that secrets have been freed */
        EXPECT_SUCCESS(s2n_kem_group_free(&kem_group_params));
        EXPECT_SUCCESS(assert_kem_params_free(&kem_group_params.kem_params));
        EXPECT_NULL(kem_group_params.ecc_params.evp_pkey);
    }
    {
        /* Happy case for s2n_kem_send_public_key() */
        struct s2n_kem_params kem_params = { .kem = &s2n_test_kem };

        DEFER_CLEANUP(struct s2n_blob io_blob = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_PUBLIC_KEY_LENGTH + 2));
        struct s2n_stuffer io_stuffer = {0};
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        EXPECT_SUCCESS(s2n_kem_send_public_key(&io_stuffer, &kem_params));

        /* {0, 2} = length of public key to follow
         * {2, 2} = test public key */
        const uint8_t expected_output[] = { 0, 2, 2, 2 };
        EXPECT_BYTEARRAY_EQUAL(io_stuffer.blob.data, expected_output, TEST_PUBLIC_KEY_LENGTH + 2);

        EXPECT_EQUAL(kem_params.private_key.size, TEST_PRIVATE_KEY_LENGTH);
        EXPECT_BYTEARRAY_EQUAL(kem_params.private_key.data, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH);
        EXPECT_EQUAL(kem_params.public_key.size, 0);
        EXPECT_NULL(kem_params.public_key.data);
        EXPECT_EQUAL(kem_params.shared_secret.size, 0);
        EXPECT_NULL(kem_params.shared_secret.data);

        /* The private key gets alloc'ed in s2n_kem_generate_keypair().
         * Nothing else should have been alloc'ed. */
        EXPECT_EQUAL(0, kem_params.public_key.allocated);
        EXPECT_EQUAL(0, kem_params.shared_secret.allocated);
        EXPECT_NOT_EQUAL(0, kem_params.private_key.allocated);
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
    }
    {
        /* Failure cases for s2n_kem_send_public_key() */
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_public_key(NULL, NULL), S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
        struct s2n_stuffer io_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_public_key(&io_stuffer, NULL), S2N_ERR_NULL);

        struct s2n_kem_params kem_params = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_public_key(&io_stuffer, &kem_params), S2N_ERR_NULL);
    }
    {
        /* Happy case for s2n_kem_send_ciphertext() */
        struct s2n_kem_params kem_params = { .kem = &s2n_test_kem };

        DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_CIPHERTEXT_LENGTH + 2));
        struct s2n_stuffer io_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        EXPECT_SUCCESS(s2n_alloc(&(kem_params.public_key), TEST_PUBLIC_KEY_LENGTH));
        memcpy_check(kem_params.public_key.data, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH);

        EXPECT_SUCCESS(s2n_kem_send_ciphertext(&io_stuffer, &kem_params));

        /* {0, 5} = length of ciphertext to follow
         * {5, 5, 5, 5, 5} = test ciphertext */
        const uint8_t expected_output[] = { 0, 5, 5, 5, 5, 5, 5 };
        EXPECT_BYTEARRAY_EQUAL(io_stuffer.blob.data, expected_output, TEST_CIPHERTEXT_LENGTH + 2);

        EXPECT_EQUAL(kem_params.shared_secret.size, TEST_SHARED_SECRET_LENGTH);
        EXPECT_BYTEARRAY_EQUAL(kem_params.shared_secret.data, TEST_SHARED_SECRET, TEST_SHARED_SECRET_LENGTH);
        EXPECT_EQUAL(kem_params.public_key.size, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_BYTEARRAY_EQUAL(kem_params.public_key.data, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_EQUAL(kem_params.private_key.size, 0);
        EXPECT_NULL(kem_params.private_key.data);

        /* We alloc'ed the public key previously in the test; the shared secret was
         * alloc'ed in Encaps; the private key should not have been alloc'ed */
        EXPECT_EQUAL(0, kem_params.private_key.allocated);
        EXPECT_NOT_EQUAL(0, kem_params.public_key.allocated);
        EXPECT_NOT_EQUAL(0, kem_params.public_key.allocated);
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
    }
    {
        /* Failure cases for s2n_kem_send_ciphertext() */
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(NULL, NULL), S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_blob io_blob = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
        struct s2n_stuffer io_stuffer = {0};
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(&io_stuffer, NULL), S2N_ERR_NULL);

        struct s2n_kem_params kem_params = {0};
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);

        kem_params.kem = &s2n_test_kem;
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);
    }
    {
        /* Happy case for s2n_kem_recv_ciphertext() */
        struct s2n_kem_params kem_params = { .kem = &s2n_test_kem };

        DEFER_CLEANUP(struct s2n_blob io_blob = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_CIPHERTEXT_LENGTH + 2));
        struct s2n_stuffer io_stuffer = {0};
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        s2n_alloc(&(kem_params.private_key), TEST_PRIVATE_KEY_LENGTH);
        memcpy_check(kem_params.private_key.data, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH);

        /* {0, 5} = length of ciphertext to follow
         * {5, 5, 5, 5, 5} = test ciphertext */
        uint8_t input[] = {0, 5, 5, 5, 5, 5, 5};
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer, input, TEST_CIPHERTEXT_LENGTH + 2));
        EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer));

        EXPECT_SUCCESS(s2n_kem_recv_ciphertext(&io_stuffer, &kem_params));

        EXPECT_EQUAL(kem_params.shared_secret.size, TEST_SHARED_SECRET_LENGTH);
        EXPECT_BYTEARRAY_EQUAL(kem_params.shared_secret.data, TEST_SHARED_SECRET, TEST_SHARED_SECRET_LENGTH);
        EXPECT_EQUAL(0, kem_params.public_key.size);
        EXPECT_NULL(kem_params.public_key.data);

        /* We alloc'ed the private key previously in the test; the shared secret was
         * alloc'ed in Decaps; the public key should not have been alloc'ed */
        EXPECT_EQUAL(0, kem_params.public_key.allocated);
        EXPECT_NOT_EQUAL(0, kem_params.private_key.allocated);
        EXPECT_NOT_EQUAL(0, kem_params.shared_secret.allocated);
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
    }
    {
        /* Failure cases for s2n_kem_recv_ciphertext() */
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(NULL, NULL), S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
        struct s2n_stuffer io_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer, NULL), S2N_ERR_NULL);

        struct s2n_kem_params kem_params = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);

        kem_params.kem = &s2n_test_kem;
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);

        /* The given ciphertext length doesn't match the KEM's actual ciphertext length */
        EXPECT_SUCCESS(s2n_alloc(&(kem_params.private_key), TEST_PRIVATE_KEY_LENGTH));
        memcpy_check(kem_params.private_key.data, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH);
        DEFER_CLEANUP(struct s2n_blob io_blob_3 = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob_3, TEST_CIPHERTEXT_LENGTH + 2));
        struct s2n_stuffer io_stuffer_3 = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer_3, &io_blob_3));
        uint8_t bad_ct_input_3[] = { 0, 2, 2, 2 };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer_3, bad_ct_input_3, 4));
        EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer_3));
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer_3, &kem_params), S2N_ERR_BAD_MESSAGE);

        /* We alloc'ed the private key previously in the test; our failure cases for
         * s2n_kem_recv_ciphertext() never reached a point where we alloc'ed anything else */
        EXPECT_NOT_EQUAL(0, kem_params.private_key.allocated);
        EXPECT_EQUAL(0, kem_params.public_key.allocated);
        EXPECT_EQUAL(0, kem_params.shared_secret.allocated);
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
    }
    {
        /* Happy case for s2n_kem_recv_public_key() */
        struct s2n_kem_params kem_params = { .kem = &s2n_test_kem };

        DEFER_CLEANUP(struct s2n_blob io_blob = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_PUBLIC_KEY_LENGTH + 2));
        struct s2n_stuffer io_stuffer = {0};
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        /* {0, 2} = length of public key to follow
         * {2, 2} = test public key */
        const uint8_t input[] = {0, 2, 2, 2};
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer, input, TEST_PUBLIC_KEY_LENGTH + 2));
        EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer));

        EXPECT_SUCCESS(s2n_kem_recv_public_key(&io_stuffer, &kem_params));

        /* s2n_kem_recv_public_key() should alloc kem_params->public_key and nothing else */
        EXPECT_EQUAL(kem_params.public_key.size, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_NOT_EQUAL(0, kem_params.public_key.allocated);
        EXPECT_BYTEARRAY_EQUAL(kem_params.public_key.data, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH);
        EXPECT_EQUAL(0, kem_params.shared_secret.allocated);
        EXPECT_EQUAL(0, kem_params.private_key.allocated);
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
    }
    {
        /* Failure cases for s2n_kem_recv_public_key() */
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(NULL, NULL), S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_blob io_blob = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
        struct s2n_stuffer io_stuffer = {0};
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(&io_stuffer, NULL), S2N_ERR_NULL);

        struct s2n_kem_params kem_params = {0};
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(&io_stuffer, &kem_params), S2N_ERR_NULL);

        kem_params.kem = &s2n_test_kem;

        /* The given public key length doesn't match the KEM's actual public key length */
        DEFER_CLEANUP(struct s2n_blob io_blob_3 = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&io_blob_3, 5));
        struct s2n_stuffer io_stuffer_3 = {0};
        EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer_3, &io_blob_3));
        uint8_t bad_pk_input_3[] = {0, 3, 3, 3, 3};
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer_3, bad_pk_input_3, 5));
        EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer_3));
        EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(&io_stuffer_3, &kem_params), S2N_ERR_BAD_MESSAGE);
    }
    {
        /* Happy case(s) for s2n_get_kem_from_extension_id() */

        /* The kem_extensions and kems arrays should be kept in sync with each other */
        kem_extension_size kem_extensions[] = {
                TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1,
                TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2,
                TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1,
                TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2,
                TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R2
        };

        const struct s2n_kem *kems[] = {
                &s2n_bike1_l1_r1,
                &s2n_bike1_l1_r2,
                &s2n_sike_p503_r1,
                &s2n_sike_p434_r2,
                &s2n_kyber_512_r2
        };

        for (size_t i = 0; i < s2n_array_len(kems); i++) {
            kem_extension_size kem_id = kem_extensions[i];
            const struct s2n_kem *returned_kem = NULL;

            EXPECT_SUCCESS(s2n_get_kem_from_extension_id(kem_id, &returned_kem));
            EXPECT_NOT_NULL(returned_kem);
            EXPECT_EQUAL(kems[i], returned_kem);
        }
    }
    {
        /* Failure cases for s2n_get_kem_from_extension_id() */
        const struct s2n_kem *returned_kem = NULL;
        kem_extension_size non_existant_kem_id = 65535;
        EXPECT_FAILURE_WITH_ERRNO(s2n_get_kem_from_extension_id(non_existant_kem_id, &returned_kem), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
    }

#endif

    END_TEST();
}
