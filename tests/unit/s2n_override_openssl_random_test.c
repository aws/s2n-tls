/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "s2n_test.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_ecc.h"
#include "crypto/s2n_drbg.h"

#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#include <openssl/engine.h>
#include <openssl/dh.h>
#include <s2n.h>

#include "testlib/s2n_testlib.h"

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
const char reference_entropy_hex[] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const char expected_dhe_key_hex[] = "0100cb5fa155609f350a0f07e340ef7dc854e38d97c7c2ba68b3f7375146ed61cd56b6caf1ac7944aa05b9fa934150ef23040fac395d640a0c2d33da6d0523f04f13702351fb8fcc4606a930dff73419d8bcf8a0037dd12b9d96e3a8121611f7d7046c29f44f8781bc47fd214b5ccd7519ff08fb83319b186d3b74b7d3f82982449c428e1ae8b1e9c9833b9cc92ee3b756e86e053ae892a480c366ee1258e3f9e14792d64c2cd9cb36108761ccd959382b966a20ba63fe7d12e496134363d58713fe52ef3e8480acffc56f33bd83ce78cf673b9f0038a98c2ec2b10e12eb1fde71996e16d6dbf994ef1c8e429d89a403027af8549619a6500e2f1b81eac593d456c30001020100c82966c203087f1bd265b756c90a3c855679f7043397f8fb4199346cbc56cbf12b68d2ceb954732c172f92f0bf727367919ad5138d6a858c734a167963870a92934356eb6c387d73d93868ec16a66d9f7a990f297093694578a96371fe66cd2fdd16a02c4cc35aa841a391382b06af92bf0a4cbce947834ec1ec2ed308d26a54459a6279f0415b2d6759f2ae6ceb07613602bbf346e045d9ba82cfc68e8d48f2d8ff04c4b8c86b9e86edba7976d2ef12f74059efa98f277ebea856c6f49e91019ba12681b9bdbfc80b58ae1f242daa69623b794bd7df61dde4de0f47f0cd0b2c42f8f316da4a82e4a7861c97674c03f815d374ddb27600d08ef9533c4f6218e1";

struct s2n_stuffer test_entropy;
int s2n_entropy_generator(struct s2n_blob *blob)
{
    GUARD(s2n_stuffer_read(&test_entropy, blob));
    return 0;
}

int main(int argc, char **argv)
{
    struct s2n_stuffer dhparams_in, dhparams_out;
    struct s2n_dh_params dh_params;
    struct s2n_blob b;
    char *dhparams_pem;

    BEGIN_TEST();

    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_EQUAL(s2n_get_private_random_bytes_used(), 0);

    /* Parse the DH params */
    b.data = (uint8_t *) dhparams_pem;
    b.size = strlen(dhparams_pem) + 1;
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, b.size));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, b.size));
    EXPECT_SUCCESS(s2n_stuffer_write(&dhparams_in, &b));
    EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));
    b.size = s2n_stuffer_data_available(&dhparams_out);
    b.data = s2n_stuffer_raw_read(&dhparams_out, b.size);
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    EXPECT_SUCCESS(s2n_dh_generate_ephemeral_key(&dh_params));
    
    /* Verify that our DRBG is called and that over-riding works */
    EXPECT_NOT_EQUAL(s2n_get_private_random_bytes_used(), 0);

    /* Setup for the second test */
    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    /* Set s2n_random to use a new fixed DRBG to test that other known answer tests with s2n_random and OpenSSL are deterministic */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&test_entropy, reference_entropy_hex));
    struct s2n_drbg drbg = {.entropy_generator = &s2n_entropy_generator};
    s2n_stack_blob(personalization_string, 32, 32);
    EXPECT_SUCCESS(s2n_drbg_instantiate(&drbg, &personalization_string, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
    EXPECT_SUCCESS(s2n_set_private_drbg_for_test(drbg));
    /* Verify we switched to a new DRBG */
    EXPECT_EQUAL(s2n_get_private_random_bytes_used(), 0);

    DEFER_CLEANUP(struct s2n_stuffer out_stuffer = {{0}}, s2n_stuffer_free);
    struct s2n_blob out_blob = {0};
    EXPECT_SUCCESS(s2n_stuffer_alloc(&out_stuffer, 4096));
    GUARD(s2n_dh_generate_ephemeral_key(&dh_params));
    GUARD(s2n_dh_params_to_p_g_Ys(&dh_params, &out_stuffer, &out_blob));

    EXPECT_EQUAL(s2n_get_private_random_bytes_used(), 304);

    DEFER_CLEANUP(struct s2n_stuffer dhe_key_stuffer = {{0}}, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&dhe_key_stuffer, expected_dhe_key_hex));
    EXPECT_EQUAL(dhe_key_stuffer.blob.size, 519);
    EXPECT_EQUAL(out_blob.size, 519);

    EXPECT_BYTEARRAY_EQUAL(dhe_key_stuffer.blob.data, out_blob.data, out_blob.size);

    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
    free(dhparams_pem);

    END_TEST();
}

#else /* defined(OPENSSL_IS_BORINGSSL) */

int main(int argc, char **argv)
{
    BEGIN_TEST();

    END_TEST();
}

#endif
