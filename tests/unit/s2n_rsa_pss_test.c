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

#include "crypto/s2n_rsa_pss.h"

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_dhe.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_random.h"

int s2n_flip_random_bit(struct s2n_blob *blob)
{
    /* Flip a random bit in the blob */
    uint64_t byte_flip_pos;
    POSIX_GUARD_RESULT(s2n_public_random(blob->size, &byte_flip_pos));
    uint64_t bit_flip_pos;
    POSIX_GUARD_RESULT(s2n_public_random(8, &bit_flip_pos));

    uint8_t mask = 0x01 << (uint8_t) bit_flip_pos;
    blob->data[byte_flip_pos] ^= mask;

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Don't use RSA-PSS certs if unsupported */
#if !RSA_PSS_CERTS_SUPPORTED
    EXPECT_FALSE(s2n_is_rsa_pss_certs_supported());
    END_TEST();
#endif
    EXPECT_TRUE(s2n_is_rsa_pss_certs_supported());

    /* Check that s2n_is_rsa_pss_certs_supported() is a superset of s2n_is_rsa_pss_signing_supported() */
    EXPECT_TRUE(s2n_is_rsa_pss_signing_supported());

    /* Positive Test: Ensure we can sign and verify a randomly generated signature.
     * Pseudocode: assert(SUCCESS == verify(Key1_public, message, sign(Key1_private, message)))
     */
    {
        struct s2n_config *server_config;
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *chain_and_key;
        struct s2n_pkey public_key = { 0 };
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());

        /* Load the Private Key */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

        /* Load the Public Key */
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&public_key, &pkey_type, &chain_and_key->cert_chain->head->raw));
        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA_PSS);

        /* Sign and Verify a Random Value to ensure that Public and Private Key Matches */
        EXPECT_SUCCESS(s2n_pkey_match(&public_key, chain_and_key->private_key));

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
        free(cert_chain_pem);
        free(private_key_pem);

        /* Verify repeated key frees.
         * (Later calls should be a no-op) */
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
    };

    /* Negative Test: Loading mismatching RSA PSS Public/Private Keys will fail.
     * Pseudocode: assert(FAILURE == load_pem_pair(Key1_public, Key2_private))
     */
    {
        struct s2n_config *server_config;
        char *leaf_cert_chain_pem;
        char *root_private_key_pem;
        struct s2n_cert_chain_and_key *misconfigured_chain_and_key;
        struct s2n_pkey public_key = { 0 };

        EXPECT_NOT_NULL(leaf_cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(root_private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, leaf_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

        /* Incorrectly reading the CA's Private Key from disk, not the Leaf's Private Key */
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, root_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(misconfigured_chain_and_key = s2n_cert_chain_and_key_new());

        /* Attempting to Load RSA_PSS Certificate with wrong RSA_PSS Key should fail */
        EXPECT_FAILURE(s2n_cert_chain_and_key_load_pem(misconfigured_chain_and_key, leaf_cert_chain_pem, root_private_key_pem));

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(misconfigured_chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
        free(leaf_cert_chain_pem);
        free(root_private_key_pem);
    };

    /* Negative Test: Ensure flipping a bit in the signature is rejected
     * Pseudocode: assert(FAILURE == verify(Key1_public, message, bitflip(sign(Key1_private, message)))
     */
    {
        struct s2n_config *server_config;
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *chain_and_key;
        struct s2n_pkey public_key = { 0 };
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());

        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_cert_chain(chain_and_key, cert_chain_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_private_key(chain_and_key, private_key_pem));

        /* Parse the leaf cert for the public key and certificate type */
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&public_key, &pkey_type, &chain_and_key->cert_chain->head->raw));
        EXPECT_NOT_EQUAL(pkey_type, S2N_PKEY_TYPE_UNKNOWN);
        EXPECT_SUCCESS(s2n_cert_set_cert_type(chain_and_key->cert_chain->head, pkey_type));

        struct s2n_pkey *private_key = chain_and_key->private_key;
        {
            EXPECT_NOT_NULL(public_key.pkey);
            EXPECT_NOT_NULL(private_key);
            EXPECT_NOT_NULL(private_key->pkey);

            /* Generate a random blob to sign and verify */
            s2n_stack_blob(random_msg, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE);
            EXPECT_OK(s2n_get_private_random_data(&random_msg));

            /* Sign/Verify API's only accept Hashes, so hash our Random Data */
            DEFER_CLEANUP(struct s2n_hash_state sign_hash = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&sign_hash));
            EXPECT_SUCCESS(s2n_hash_init(&sign_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&sign_hash, random_msg.data, random_msg.size));

            DEFER_CLEANUP(struct s2n_hash_state verify_hash = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&verify_hash));
            EXPECT_SUCCESS(s2n_hash_init(&verify_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&verify_hash, random_msg.data, random_msg.size));

            /* Sign and Verify the Hash of the Random Blob */
            s2n_stack_blob(signature_data, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE);
            EXPECT_SUCCESS(s2n_pkey_sign(private_key, S2N_SIGNATURE_RSA_PSS_PSS, &sign_hash, &signature_data));

            /* Flip a random bit in the signature */
            EXPECT_SUCCESS(s2n_flip_random_bit(&signature_data));
            EXPECT_FAILURE(s2n_pkey_verify(&public_key, S2N_SIGNATURE_RSA_PSS_PSS, &verify_hash, &signature_data));
        };

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
        free(cert_chain_pem);
        free(private_key_pem);
    };

    /* Negative Test: Ensure Verification with wrong key fails
     * Pseudocode: assert(FAILURE == verify(Key2_public, message, sign(Key1_private, message)))
     */
    {
        struct s2n_config *server_config;
        char *root_cert_chain_pem;
        char *root_private_key_pem;
        char *leaf_cert_chain_pem;
        char *leaf_private_key_pem;
        struct s2n_cert_chain_and_key *root_chain_and_key;
        struct s2n_cert_chain_and_key *leaf_chain_and_key;
        struct s2n_pkey root_public_key = { 0 };
        struct s2n_pkey leaf_public_key = { 0 };
        s2n_pkey_type root_pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        s2n_pkey_type leaf_pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_NOT_NULL(root_cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(root_private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(leaf_cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(leaf_private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_CERT, root_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, root_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, leaf_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_KEY, leaf_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(root_chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(leaf_chain_and_key = s2n_cert_chain_and_key_new());

        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_cert_chain(root_chain_and_key, root_cert_chain_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_private_key(root_chain_and_key, root_private_key_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_cert_chain(leaf_chain_and_key, leaf_cert_chain_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_private_key(leaf_chain_and_key, leaf_private_key_pem));

        /* Parse the cert for the public key and certificate type */
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&root_public_key, &root_pkey_type, &root_chain_and_key->cert_chain->head->raw));
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&leaf_public_key, &leaf_pkey_type, &leaf_chain_and_key->cert_chain->head->raw));
        EXPECT_NOT_EQUAL(root_pkey_type, S2N_PKEY_TYPE_UNKNOWN);
        EXPECT_NOT_EQUAL(leaf_pkey_type, S2N_PKEY_TYPE_UNKNOWN);

        EXPECT_SUCCESS(s2n_cert_set_cert_type(root_chain_and_key->cert_chain->head, root_pkey_type));
        EXPECT_SUCCESS(s2n_cert_set_cert_type(leaf_chain_and_key->cert_chain->head, leaf_pkey_type));

        struct s2n_pkey *root_private_key = root_chain_and_key->private_key;
        struct s2n_pkey *leaf_private_key = leaf_chain_and_key->private_key;
        {
            EXPECT_NOT_NULL(root_public_key.pkey);
            EXPECT_NOT_NULL(leaf_public_key.pkey);

            EXPECT_NOT_NULL(root_private_key);
            EXPECT_NOT_NULL(root_private_key->pkey);
            EXPECT_NOT_NULL(leaf_private_key);
            EXPECT_NOT_NULL(leaf_private_key->pkey);

            /* Generate a random blob to sign and verify */
            s2n_stack_blob(random_msg, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE);
            EXPECT_OK(s2n_get_private_random_data(&random_msg));

            /* Sign/Verify API's only accept Hashes, so hash our Random Data */
            DEFER_CLEANUP(struct s2n_hash_state sign_hash = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&sign_hash));
            EXPECT_SUCCESS(s2n_hash_init(&sign_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&sign_hash, random_msg.data, random_msg.size));

            DEFER_CLEANUP(struct s2n_hash_state verify_hash = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&verify_hash));
            EXPECT_SUCCESS(s2n_hash_init(&verify_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&verify_hash, random_msg.data, random_msg.size));

            /* Sign and Verify the Hash of the Random Blob */
            s2n_stack_blob(signature_data, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE);

            /* Sign with Root's Key, but verify with Leaf's Key. This should fail. */
            EXPECT_SUCCESS(s2n_pkey_sign(root_private_key, S2N_SIGNATURE_RSA_PSS_PSS, &sign_hash, &signature_data));
            EXPECT_FAILURE(s2n_pkey_verify(&leaf_public_key, S2N_SIGNATURE_RSA_PSS_PSS, &verify_hash, &signature_data));
        };

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(root_chain_and_key));
        EXPECT_SUCCESS(s2n_pkey_free(&root_public_key));
        free(root_cert_chain_pem);
        free(root_private_key_pem);

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(leaf_chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&leaf_public_key));
        free(leaf_cert_chain_pem);
        free(leaf_private_key_pem);
    };

    /* Negative Test: Ensure flipping a bit in message given to verification fails
     * Pseudocode: assert(FAILURE == verify(Key1_public, bitflip(message), sign(Key1_private, message)))
     */
    {
        struct s2n_config *server_config;
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *chain_and_key;
        struct s2n_pkey public_key = { 0 };
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());

        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_cert_chain(chain_and_key, cert_chain_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_private_key(chain_and_key, private_key_pem));

        /* Parse the leaf cert for the public key and certificate type */
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&public_key, &pkey_type, &chain_and_key->cert_chain->head->raw));
        EXPECT_NOT_EQUAL(pkey_type, S2N_PKEY_TYPE_UNKNOWN);
        EXPECT_SUCCESS(s2n_cert_set_cert_type(chain_and_key->cert_chain->head, pkey_type));

        struct s2n_pkey *private_key = chain_and_key->private_key;
        {
            EXPECT_NOT_NULL(public_key.pkey);
            EXPECT_NOT_NULL(private_key);
            EXPECT_NOT_NULL(private_key->pkey);

            /* Generate a random blob to sign and verify */
            s2n_stack_blob(random_msg, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE);
            EXPECT_OK(s2n_get_private_random_data(&random_msg));

            /* Sign/Verify API's only accept Hashes, so hash our Random Data */
            DEFER_CLEANUP(struct s2n_hash_state sign_hash = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&sign_hash));
            EXPECT_SUCCESS(s2n_hash_init(&sign_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&sign_hash, random_msg.data, random_msg.size));

            /* Flip a random bit in the message before verification */
            EXPECT_SUCCESS(s2n_flip_random_bit(&random_msg));

            DEFER_CLEANUP(struct s2n_hash_state verify_hash = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&verify_hash));
            EXPECT_SUCCESS(s2n_hash_init(&verify_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&verify_hash, random_msg.data, random_msg.size));

            /* Sign and Verify the Hash of the Random Blob */
            s2n_stack_blob(signature_data, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE);
            EXPECT_SUCCESS(s2n_pkey_sign(private_key, S2N_SIGNATURE_RSA_PSS_PSS, &sign_hash, &signature_data));
            EXPECT_FAILURE(s2n_pkey_verify(&public_key, S2N_SIGNATURE_RSA_PSS_PSS, &verify_hash, &signature_data));
        };

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
        free(cert_chain_pem);
        free(private_key_pem);
    };

    END_TEST();
}
