/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <s2n.h>

static uint8_t dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n" "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n" "-----END DH PARAMETERS-----\n";

static int mock_called = 0;

int mock_openssl_compat_rand(unsigned char *buf, int num)
{
    int r = s2n_get_random_data(buf, num);
    if (r < 0) {
        return 0;
    }

    mock_called = 1;

    return 1;
}

void mock_openssl_compat_seed(const void *buf, int num)
{

}

int mock_openssl_compat_status()
{
    return 1;
}

void mock_openssl_compat_cleanup()
{

}

void mock_openssl_compat_add(const void *buf, int num, double entropy)
{

}

RAND_METHOD mock_openssl_rand_method = {
    .seed = mock_openssl_compat_seed,
    .bytes = mock_openssl_compat_rand,
    .cleanup = mock_openssl_compat_cleanup,
    .add = mock_openssl_compat_add,
    .pseudorand = mock_openssl_compat_rand,
    .status = mock_openssl_compat_status
};

int main(int argc, char **argv)
{
    struct s2n_stuffer dhparams_in, dhparams_out;
    struct s2n_dh_params dh_params;
    struct s2n_blob b;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_init());

    /* Over-ride OpenSSL's PRNG */
    RAND_set_rand_method(&mock_openssl_rand_method);

    /* Parse the DH params */
    b.data = dhparams;
    b.size = sizeof(dhparams);
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, sizeof(dhparams)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, sizeof(dhparams)));
    EXPECT_SUCCESS(s2n_stuffer_write(&dhparams_in, &b));
    EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));
    b.size = s2n_stuffer_data_available(&dhparams_out);
    b.data = s2n_stuffer_raw_read(&dhparams_out, b.size);
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    EXPECT_EQUAL(mock_called, 0);

    EXPECT_SUCCESS(s2n_dh_generate_ephemeral_key(&dh_params));

    /* Verify that our mock random is called and that over-riding works */
    EXPECT_EQUAL(mock_called, 1);

    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));

    END_TEST();
}
