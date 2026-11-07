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

#include <stdlib.h>
#include <string.h>

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    struct s2n_stuffer certificate_in = { 0 }, certificate_out = { 0 };
    struct s2n_stuffer dhparams_in = { 0 }, dhparams_out = { 0 };
    struct s2n_stuffer rsa_key_in = { 0 }, rsa_key_out = { 0 };
    struct s2n_blob b = { 0 };
    char *leaf_cert_pem = NULL;
    char *cert_chain_pem = NULL;
    char *private_key_pem = NULL;
    char *dhparams_pem = NULL;
    struct s2n_cert_chain_and_key *chain_and_key = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(leaf_cert_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&rsa_key_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&rsa_key_out, S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_LEAF_CERT, leaf_cert_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) leaf_cert_pem, strlen(leaf_cert_pem) + 1));
    EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));

    EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) private_key_pem, strlen(private_key_pem) + 1));
    EXPECT_SUCCESS(s2n_stuffer_write(&rsa_key_in, &b));

    EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) dhparams_pem, strlen(dhparams_pem) + 1));
    EXPECT_SUCCESS(s2n_stuffer_write(&dhparams_in, &b));

    int type = 0;
    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_private_key_from_pem(&rsa_key_in, &rsa_key_out, &type));
    EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));
    EXPECT_EQUAL(type, EVP_PKEY_RSA);

    struct s2n_pkey priv_key = { 0 };
    struct s2n_pkey pub_key = { 0 };
    s2n_pkey_type pkey_type = { 0 };

    uint32_t available_size = 0;
    available_size = s2n_stuffer_data_available(&certificate_out);
    EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&certificate_out, available_size), available_size));
    EXPECT_OK(s2n_asn1der_to_public_key_and_type(&pub_key, &pkey_type, &b));

    /* Test without a type hint */
    int wrong_type = 0;
    EXPECT_NOT_EQUAL(wrong_type, EVP_PKEY_RSA);

    available_size = s2n_stuffer_data_available(&rsa_key_out);
    EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&rsa_key_out, available_size), available_size));
    EXPECT_OK(s2n_asn1der_to_private_key(&priv_key, &b, wrong_type));

    EXPECT_SUCCESS(s2n_pkey_match(&pub_key, &priv_key));

    struct s2n_config *config = NULL;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    struct s2n_dh_params dh_params = { 0 };
    available_size = s2n_stuffer_data_available(&dhparams_out);
    EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&dhparams_out, available_size), available_size));
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

    /* Try signing and verification with RSA */
    uint8_t inputpad[] = "Hello world!";
    struct s2n_blob signature = { 0 };
    struct s2n_hash_state tls10_one = { 0 };
    struct s2n_hash_state tls10_two = { 0 };
    struct s2n_hash_state tls12_one = { 0 };
    struct s2n_hash_state tls12_two = { 0 };

    uint32_t maximum_signature_length = 0;
    EXPECT_OK(s2n_pkey_size(&pub_key, &maximum_signature_length));
    EXPECT_SUCCESS(s2n_alloc(&signature, maximum_signature_length));

    if (s2n_hash_is_available(S2N_HASH_MD5_SHA1)) {
        /* TLS 1.0 use of RSA with DHE is not permitted when FIPS mode is set */
        EXPECT_SUCCESS(s2n_hash_new(&tls10_one));
        EXPECT_SUCCESS(s2n_hash_new(&tls10_two));

        EXPECT_SUCCESS(s2n_hash_init(&tls10_one, S2N_HASH_MD5_SHA1));
        EXPECT_SUCCESS(s2n_hash_init(&tls10_two, S2N_HASH_MD5_SHA1));

        EXPECT_SUCCESS(s2n_hash_update(&tls10_one, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_hash_update(&tls10_two, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_pkey_sign(&priv_key, S2N_SIGNATURE_RSA, &tls10_one, &signature));
        EXPECT_SUCCESS(s2n_pkey_verify(&pub_key, S2N_SIGNATURE_RSA, &tls10_two, &signature));

        EXPECT_SUCCESS(s2n_hash_free(&tls10_one));
        EXPECT_SUCCESS(s2n_hash_free(&tls10_two));
    }

    /* TLS 1.2 use of RSA with DHE is permitted for FIPS and non-FIPS */
    EXPECT_SUCCESS(s2n_hash_new(&tls12_one));
    EXPECT_SUCCESS(s2n_hash_new(&tls12_two));

    EXPECT_SUCCESS(s2n_hash_init(&tls12_one, S2N_HASH_SHA1));
    EXPECT_SUCCESS(s2n_hash_init(&tls12_two, S2N_HASH_SHA1));

    EXPECT_SUCCESS(s2n_hash_update(&tls12_one, inputpad, sizeof(inputpad)));
    EXPECT_SUCCESS(s2n_hash_update(&tls12_two, inputpad, sizeof(inputpad)));
    EXPECT_SUCCESS(s2n_pkey_sign(&priv_key, S2N_SIGNATURE_RSA, &tls12_one, &signature));
    EXPECT_SUCCESS(s2n_pkey_verify(&pub_key, S2N_SIGNATURE_RSA, &tls12_two, &signature));

    EXPECT_SUCCESS(s2n_hash_free(&tls12_one));
    EXPECT_SUCCESS(s2n_hash_free(&tls12_two));

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_pkey_free(&priv_key));
    EXPECT_SUCCESS(s2n_pkey_free(&pub_key));
    EXPECT_SUCCESS(s2n_free(&signature));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&rsa_key_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&rsa_key_out));
    free(cert_chain_pem);
    free(leaf_cert_pem);
    free(private_key_pem);
    free(dhparams_pem);

    END_TEST();
}
