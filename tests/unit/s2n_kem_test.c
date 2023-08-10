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
#include "tls/s2n_kem.h"

#include "crypto/s2n_ecc_evp.h"
#include "pq-crypto/s2n_pq.h"
#include "tests/s2n_test.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"

#define TEST_PUBLIC_KEY_LENGTH 2
const uint8_t TEST_PUBLIC_KEY[] = { 2, 2 };
#define TEST_PRIVATE_KEY_LENGTH 3
const uint8_t TEST_PRIVATE_KEY[] = { 3, 3, 3 };
#define TEST_SHARED_SECRET_LENGTH 4
const uint8_t TEST_SHARED_SECRET[] = { 4, 4, 4, 4 };
#define TEST_CIPHERTEXT_LENGTH 5
const uint8_t TEST_CIPHERTEXT[] = { 5, 5, 5, 5, 5 };

static const uint8_t kyber_iana[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 };
static const uint8_t classic_ecdhe_iana[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA };

int alloc_test_kem_params(struct s2n_kem_params *kem_params)
{
    POSIX_GUARD(s2n_alloc(&(kem_params->private_key), TEST_PRIVATE_KEY_LENGTH));
    struct s2n_stuffer private_key_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&private_key_stuffer, &(kem_params->private_key)));
    POSIX_GUARD(s2n_stuffer_write_bytes(&private_key_stuffer, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH));

    POSIX_GUARD(s2n_alloc(&(kem_params->public_key), TEST_PUBLIC_KEY_LENGTH));
    struct s2n_stuffer public_key_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&public_key_stuffer, &(kem_params->public_key)));
    POSIX_GUARD(s2n_stuffer_write_bytes(&public_key_stuffer, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH));

    POSIX_GUARD(s2n_alloc(&(kem_params->shared_secret), TEST_SHARED_SECRET_LENGTH));
    struct s2n_stuffer shared_secret_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&shared_secret_stuffer, &(kem_params->shared_secret)));
    POSIX_GUARD(s2n_stuffer_write_bytes(&shared_secret_stuffer, TEST_SHARED_SECRET, TEST_SHARED_SECRET_LENGTH));

    POSIX_ENSURE_NE(0, kem_params->private_key.allocated);
    POSIX_ENSURE_NE(0, kem_params->public_key.allocated);
    POSIX_ENSURE_NE(0, kem_params->shared_secret.allocated);

    return S2N_SUCCESS;
}

int assert_kem_params_free(struct s2n_kem_params *kem_params)
{
    POSIX_ENSURE_EQ(NULL, kem_params->private_key.data);
    POSIX_ENSURE_EQ(0, kem_params->private_key.size);
    POSIX_ENSURE_EQ(0, kem_params->private_key.allocated);

    POSIX_ENSURE_EQ(NULL, kem_params->public_key.data);
    POSIX_ENSURE_EQ(0, kem_params->public_key.size);
    POSIX_ENSURE_EQ(0, kem_params->public_key.allocated);

    POSIX_ENSURE_EQ(NULL, kem_params->shared_secret.data);
    POSIX_ENSURE_EQ(0, kem_params->shared_secret.size);
    POSIX_ENSURE_EQ(0, kem_params->shared_secret.allocated);

    return S2N_SUCCESS;
}

int s2n_test_generate_keypair(const struct s2n_kem *kem, unsigned char *public_key, unsigned char *private_key)
{
    memset(public_key, kem->public_key_length, kem->public_key_length);
    memset(private_key, kem->private_key_length, kem->private_key_length);
    return 0;
}

int s2n_test_encrypt(const struct s2n_kem *kem, unsigned char *ciphertext, unsigned char *shared_secret, const unsigned char *public_key)
{
    POSIX_GUARD(memcmp(public_key, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH));
    memset(ciphertext, kem->ciphertext_length, kem->ciphertext_length);
    memset(shared_secret, kem->shared_secret_key_length, kem->shared_secret_key_length);
    return 0;
}

int s2n_test_decrypt(const struct s2n_kem *kem, unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key)
{
    POSIX_GUARD(memcmp(ciphertext, TEST_CIPHERTEXT, TEST_CIPHERTEXT_LENGTH));
    POSIX_GUARD(memcmp(private_key, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH));
    memset(shared_secret, kem->shared_secret_key_length, kem->shared_secret_key_length);
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

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Run KEM tests that don't depend on the value of len_prefix */
    {
        /* Regression test for network parsing data of expected sizes */
        EXPECT_EQUAL(sizeof(kem_extension_size), 2);
        EXPECT_EQUAL(sizeof(kem_public_key_size), 2);
        EXPECT_EQUAL(sizeof(kem_private_key_size), 2);
        EXPECT_EQUAL(sizeof(kem_shared_secret_size), 2);
        EXPECT_EQUAL(sizeof(kem_ciphertext_key_size), 2);
    };
    {
        const struct s2n_iana_to_kem *compatible_params = NULL;
        EXPECT_FAILURE_WITH_ERRNO(s2n_cipher_suite_to_kem(classic_ecdhe_iana, &compatible_params), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_NULL(compatible_params);

        EXPECT_SUCCESS(s2n_cipher_suite_to_kem(kyber_iana, &compatible_params));
        EXPECT_NOT_NULL(compatible_params);
        EXPECT_EQUAL(compatible_params->kem_count, 1);
        EXPECT_EQUAL(compatible_params->kems[0]->kem_extension_id, s2n_kyber_512_r3.kem_extension_id);
    };
    {
        /* Tests for s2n_kem_free() */
        EXPECT_SUCCESS(s2n_kem_free(NULL));

        struct s2n_kem_params kem_params = { 0 };
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));

        /* Fill kem_params with secrets and ensure that they have been freed */
        EXPECT_SUCCESS(alloc_test_kem_params(&kem_params));
        EXPECT_SUCCESS(s2n_kem_free(&kem_params));
        EXPECT_SUCCESS(assert_kem_params_free(&kem_params));
    };
    {
        /* Tests for s2n_kem_group_free() */
        EXPECT_SUCCESS(s2n_kem_group_free(NULL));

        struct s2n_kem_group_params kem_group_params = { 0 };
        EXPECT_SUCCESS(s2n_kem_group_free(&kem_group_params));

        /* Fill the kem_group_params with secrets */
        EXPECT_SUCCESS(alloc_test_kem_params(&kem_group_params.kem_params));
        struct s2n_stuffer wire = { 0 };
        POSIX_GUARD(s2n_stuffer_growable_alloc(&wire, 1024));
        kem_group_params.ecc_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        POSIX_GUARD(s2n_ecdhe_parameters_send(&kem_group_params.ecc_params, &wire));
        POSIX_GUARD(s2n_stuffer_free(&wire));
        EXPECT_NOT_NULL(kem_group_params.ecc_params.evp_pkey);

        /* Ensure that secrets have been freed */
        EXPECT_SUCCESS(s2n_kem_group_free(&kem_group_params));
        EXPECT_SUCCESS(assert_kem_params_free(&kem_group_params.kem_params));
        EXPECT_NULL(kem_group_params.ecc_params.evp_pkey);
    };
    {
        /* Happy case(s) for s2n_get_kem_from_extension_id() */

        /* The kem_extensions and kems arrays should be kept in sync with each other */
        kem_extension_size kem_extensions[] = {
            TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R3,
        };

        const struct s2n_kem *kems[] = {
            &s2n_kyber_512_r3,
        };

        for (size_t i = 0; i < s2n_array_len(kems); i++) {
            kem_extension_size kem_id = kem_extensions[i];
            const struct s2n_kem *returned_kem = NULL;

            EXPECT_SUCCESS(s2n_get_kem_from_extension_id(kem_id, &returned_kem));
            EXPECT_NOT_NULL(returned_kem);
            EXPECT_EQUAL(kems[i], returned_kem);
        }
    };
    {
        /* Failure cases for s2n_get_kem_from_extension_id() */
        const struct s2n_kem *returned_kem = NULL;
        kem_extension_size non_existent_kem_id = 65535;
        EXPECT_FAILURE_WITH_ERRNO(s2n_get_kem_from_extension_id(non_existent_kem_id, &returned_kem), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
    };

    /* If KEM tests depend on len_prefix, test with both possible values */
    for (int len_prefixed = 0; len_prefixed < 2; len_prefixed++) {
        {
            struct s2n_kem_params server_kem_params = { 0 };
            server_kem_params.kem = &s2n_test_kem;
            server_kem_params.len_prefixed = len_prefixed;
            EXPECT_SUCCESS(s2n_alloc(&server_kem_params.public_key, TEST_PUBLIC_KEY_LENGTH));
            EXPECT_OK(s2n_kem_generate_keypair(&server_kem_params));
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
            client_kem_params.len_prefixed = len_prefixed;
            /* This would be handled by client/server key exchange methods which isn't being tested */
            POSIX_GUARD(s2n_alloc(&client_kem_params.public_key, TEST_PUBLIC_KEY_LENGTH));
            memset(client_kem_params.public_key.data, TEST_PUBLIC_KEY_LENGTH, TEST_PUBLIC_KEY_LENGTH);

            DEFER_CLEANUP(struct s2n_blob ciphertext = { 0 }, s2n_free);
            POSIX_GUARD(s2n_alloc(&ciphertext, TEST_CIPHERTEXT_LENGTH));

            EXPECT_OK(s2n_kem_encapsulate(&client_kem_params, &ciphertext));
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

            EXPECT_OK(s2n_kem_decapsulate(&server_kem_params, &ciphertext));
            EXPECT_EQUAL(TEST_SHARED_SECRET_LENGTH, server_kem_params.shared_secret.size);
            EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, server_kem_params.shared_secret.data, TEST_SHARED_SECRET_LENGTH);
            /* Decaps shouldn't modify the public or private keys */
            EXPECT_EQUAL(TEST_PUBLIC_KEY_LENGTH, server_kem_params.public_key.size);
            EXPECT_BYTEARRAY_EQUAL(TEST_PUBLIC_KEY, server_kem_params.public_key.data, TEST_PUBLIC_KEY_LENGTH);
            EXPECT_EQUAL(TEST_PRIVATE_KEY_LENGTH, server_kem_params.private_key.size);
            EXPECT_BYTEARRAY_EQUAL(TEST_PRIVATE_KEY, server_kem_params.private_key.data, TEST_PRIVATE_KEY_LENGTH);

            EXPECT_SUCCESS(s2n_kem_free(&server_kem_params));
            EXPECT_SUCCESS(s2n_kem_free(&client_kem_params));
        };
        {
            /* Happy case for s2n_kem_send_public_key() */
            struct s2n_kem_params kem_params = { .kem = &s2n_test_kem, .len_prefixed = len_prefixed };

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_PUBLIC_KEY_LENGTH + 2));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            EXPECT_SUCCESS(s2n_kem_send_public_key(&io_stuffer, &kem_params));

            /* {0, 2} = length of public key to follow
             * {2, 2} = test public key */
            uint8_t prefixed_output[] = { 0, 2, 2, 2 };
            uint8_t unprefixed_output[] = { 2, 2 };

            uint8_t *output = unprefixed_output;
            uint16_t output_len = TEST_PUBLIC_KEY_LENGTH;

            if (len_prefixed) {
                output = prefixed_output;
                output_len = TEST_PUBLIC_KEY_LENGTH + 2;
            }

            EXPECT_BYTEARRAY_EQUAL(io_stuffer.blob.data, output, output_len);

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
        };
        {
            /* Failure cases for s2n_kem_send_public_key() */
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_public_key(NULL, NULL), S2N_ERR_NULL);

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_public_key(&io_stuffer, NULL), S2N_ERR_NULL);

            struct s2n_kem_params kem_params = { 0 };
            kem_params.len_prefixed = len_prefixed;
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_public_key(&io_stuffer, &kem_params), S2N_ERR_NULL);
        };
        {
            /* Happy case for s2n_kem_send_ciphertext() */
            struct s2n_kem_params kem_params = { .kem = &s2n_test_kem, .len_prefixed = len_prefixed };

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_CIPHERTEXT_LENGTH + 2));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            EXPECT_SUCCESS(s2n_alloc(&(kem_params.public_key), TEST_PUBLIC_KEY_LENGTH));
            POSIX_CHECKED_MEMCPY(kem_params.public_key.data, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH);

            EXPECT_SUCCESS(s2n_kem_send_ciphertext(&io_stuffer, &kem_params));

            /* {0, 5} = length of ciphertext to follow
             * {5, 5, 5, 5, 5} = test ciphertext */
            uint8_t prefixed_output[] = { 0, 5, 5, 5, 5, 5, 5 };
            uint8_t unprefixed_output[] = { 5, 5, 5, 5, 5 };

            uint8_t *output = unprefixed_output;
            uint16_t output_len = TEST_CIPHERTEXT_LENGTH;

            if (len_prefixed) {
                output = prefixed_output;
                output_len = TEST_CIPHERTEXT_LENGTH + 2;
            }

            EXPECT_BYTEARRAY_EQUAL(io_stuffer.blob.data, output, output_len);

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
        };
        {
            /* Failure cases for s2n_kem_send_ciphertext() */
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(NULL, NULL), S2N_ERR_NULL);

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(&io_stuffer, NULL), S2N_ERR_NULL);

            struct s2n_kem_params kem_params = { 0 };
            kem_params.len_prefixed = len_prefixed;
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);

            kem_params.kem = &s2n_test_kem;
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_send_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);
        };
        {
            /* Happy case for s2n_kem_recv_ciphertext() */
            struct s2n_kem_params kem_params = { .kem = &s2n_test_kem, .len_prefixed = len_prefixed };

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_CIPHERTEXT_LENGTH + 2));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            s2n_alloc(&(kem_params.private_key), TEST_PRIVATE_KEY_LENGTH);
            POSIX_CHECKED_MEMCPY(kem_params.private_key.data, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH);

            /* {0, 5} = length of ciphertext to follow
             * {5, 5, 5, 5, 5} = test ciphertext */
            uint8_t prefixed_input[] = { 0, 5, 5, 5, 5, 5, 5 };
            uint8_t unprefixed_input[] = { 5, 5, 5, 5, 5 };

            uint8_t *input = unprefixed_input;
            uint16_t input_len = TEST_CIPHERTEXT_LENGTH;
            if (len_prefixed) {
                input = prefixed_input;
                input_len = TEST_CIPHERTEXT_LENGTH + 2;
            }

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer, input, input_len));
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
        };
        {
            /* Failure cases for s2n_kem_recv_ciphertext() */
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(NULL, NULL), S2N_ERR_NULL);

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer, NULL), S2N_ERR_NULL);

            struct s2n_kem_params kem_params = { 0 };
            kem_params.len_prefixed = len_prefixed;
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);

            kem_params.kem = &s2n_test_kem;
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer, &kem_params), S2N_ERR_NULL);

            /* The given ciphertext length doesn't match the KEM's actual ciphertext length */
            EXPECT_SUCCESS(s2n_alloc(&(kem_params.private_key), TEST_PRIVATE_KEY_LENGTH));
            POSIX_CHECKED_MEMCPY(kem_params.private_key.data, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH);
            DEFER_CLEANUP(struct s2n_blob io_blob_3 = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob_3, TEST_CIPHERTEXT_LENGTH + 2));
            struct s2n_stuffer io_stuffer_3 = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer_3, &io_blob_3));
            uint8_t bad_ct_input_3[] = { 0, 2, 2, 2 };
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer_3, bad_ct_input_3, 4));
            EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer_3));

            if (len_prefixed) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_ciphertext(&io_stuffer_3, &kem_params), S2N_ERR_BAD_MESSAGE);
            }

            /* We alloc'ed the private key previously in the test; our failure cases for
             * s2n_kem_recv_ciphertext() never reached a point where we alloc'ed anything else */
            EXPECT_NOT_EQUAL(0, kem_params.private_key.allocated);
            EXPECT_EQUAL(0, kem_params.public_key.allocated);
            EXPECT_EQUAL(0, kem_params.shared_secret.allocated);
            EXPECT_SUCCESS(s2n_kem_free(&kem_params));
        };
        {
            /* Happy case for s2n_kem_recv_public_key() */
            struct s2n_kem_params kem_params = { .kem = &s2n_test_kem, .len_prefixed = len_prefixed };

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, TEST_PUBLIC_KEY_LENGTH + 2));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            /* {0, 2} = length of public key to follow
             * {2, 2} = test public key */
            uint8_t prefixed_input[] = { 0, 2, 2, 2 };
            uint8_t unprefixed_input[] = { 2, 2 };

            uint8_t *input = unprefixed_input;
            uint16_t input_len = TEST_PUBLIC_KEY_LENGTH;

            if (len_prefixed) {
                input = prefixed_input;
                input_len = TEST_PUBLIC_KEY_LENGTH + 2;
            }

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer, input, input_len));
            EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer));

            EXPECT_SUCCESS(s2n_kem_recv_public_key(&io_stuffer, &kem_params));

            /* s2n_kem_recv_public_key() should alloc kem_params->public_key and nothing else */
            EXPECT_EQUAL(kem_params.public_key.size, TEST_PUBLIC_KEY_LENGTH);
            EXPECT_NOT_EQUAL(0, kem_params.public_key.allocated);
            EXPECT_BYTEARRAY_EQUAL(kem_params.public_key.data, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH);
            EXPECT_EQUAL(0, kem_params.shared_secret.allocated);
            EXPECT_EQUAL(0, kem_params.private_key.allocated);
            EXPECT_SUCCESS(s2n_kem_free(&kem_params));
        };
        {
            /* Failure cases for s2n_kem_recv_public_key() */
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(NULL, NULL), S2N_ERR_NULL);

            DEFER_CLEANUP(struct s2n_blob io_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob, 1));
            struct s2n_stuffer io_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer, &io_blob));

            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(&io_stuffer, NULL), S2N_ERR_NULL);

            struct s2n_kem_params kem_params = { 0 };
            kem_params.len_prefixed = len_prefixed;
            EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(&io_stuffer, &kem_params), S2N_ERR_NULL);

            kem_params.kem = &s2n_test_kem;

            /* The given public key length doesn't match the KEM's actual public key length */
            DEFER_CLEANUP(struct s2n_blob io_blob_3 = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&io_blob_3, 5));
            struct s2n_stuffer io_stuffer_3 = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&io_stuffer_3, &io_blob_3));
            uint8_t bad_pk_input_3[] = { 0, 3, 3, 3, 3 };
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer_3, bad_pk_input_3, 5));
            EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer_3));
            if (len_prefixed) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_kem_recv_public_key(&io_stuffer_3, &kem_params), S2N_ERR_BAD_MESSAGE);
            }
        };
    }

    END_TEST();
}
