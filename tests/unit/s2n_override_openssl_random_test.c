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

#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

#include <openssl/engine.h>
#include <openssl/dh.h>
#include <s2n.h>

#include "testlib/s2n_testlib.h"

#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_FIPS) && !defined(LIBRESSL_VERSION_NUMBER)

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

