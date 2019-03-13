/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#include <openssl/engine.h>
#include <openssl/dh.h>
#include <s2n.h>

#include "testlib/s2n_testlib.h"

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
const char reference_entropy_hex[] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const char expected_ecdhe_key_hex[] = "03001741044c0fba19385697d2f359558aeac99a955678001a7777c26e725f505032d882a3ae1787d6c512f3322f843ebbd70e229bb085f15e8f1dc7424e9d9c8b95db4165";

int main(int argc, char **argv)
{
    BEGIN_TEST();
    /* Begin test calls s2n_init which sets OpenSSL to use s2n_get_private_random_data */
    EXPECT_EQUAL(s2n_get_private_random_bytes_used(), 0);
    struct s2n_ecc_params ecc_params = {.negotiated_curve = &s2n_ecc_supported_curves[0]};
    EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&ecc_params));
    EXPECT_EQUAL(s2n_get_private_random_bytes_used(), 64);
    EXPECT_SUCCESS(s2n_ecc_params_free(&ecc_params));

    /* Set OpenSSL to use a new RNG to test that other known answer tests with OpenSSL will work */
    EXPECT_SUCCESS(s2n_drbg_enable_dangerous_modes());
    EXPECT_SUCCESS(s2n_set_openssl_rng_seed(reference_entropy_hex, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
    EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&ecc_params));

    /* No Additional bytes should have been used from the original private data */
    EXPECT_EQUAL(s2n_get_private_random_bytes_used(), 64);

    DEFER_CLEANUP(struct s2n_stuffer out_stuffer = {{0}}, s2n_stuffer_free);
    struct s2n_blob out_blob = {0};
    EXPECT_SUCCESS(s2n_stuffer_alloc(&out_stuffer, 512));

    EXPECT_SUCCESS(s2n_ecc_write_ecc_params(&ecc_params, &out_stuffer, &out_blob));

    struct s2n_stuffer ecdhe_key_stuffer = {{0}};
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&ecdhe_key_stuffer, expected_ecdhe_key_hex));

    EXPECT_BYTEARRAY_EQUAL(ecdhe_key_stuffer.blob.data, out_blob.data, 69);

    EXPECT_SUCCESS(s2n_ecc_params_free(&ecc_params));

    END_TEST();
}

#else

int main(int argc, char **argv)
{
    BEGIN_TEST();

    END_TEST();
}

#endif
