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

#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <stddef.h>

#include "crypto/s2n_drbg.h"
#include "crypto/s2n_openssl.h"
#include "utils/s2n_safety.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"
#include "s2n_testlib.h"

static struct s2n_stuffer entropy = {{0}};
static int fake_urandom_data(struct s2n_blob *blob)
{
    GUARD(s2n_stuffer_read(&entropy, blob));
    return 0;
}
static struct s2n_drbg test_drbg = {.entropy_generator = fake_urandom_data};
static int s2n_openssl_compat_rand(unsigned char *buf, int num)
{
    struct s2n_blob out = {.data = buf,.size = num };

    if (s2n_drbg_generate(&test_drbg, &out) < 0) {
        return 0;
    }
    return 1;
}

RAND_METHOD s2n_test_openssl_rand_method = {
        .seed = NULL,
        .bytes = s2n_openssl_compat_rand,
        .cleanup = NULL,
        .add = NULL,
        .pseudorand = s2n_openssl_compat_rand,
        .status = s2n_openssl_compat_status
};

int s2n_set_openssl_rng_seed(const char *str, const s2n_drbg_mode drbg_mode)
{
    /* Free old resources used by OpenSSL */
    GUARD(s2n_rand_cleanup());

    GUARD(s2n_stuffer_alloc_ro_from_hex_string(&entropy, str));
    /* For now nothing uses a personalization string for testing */
    s2n_stack_blob(personalization_string, 32, 32);
    GUARD(s2n_drbg_instantiate(&test_drbg, &personalization_string, drbg_mode));

    GUARD(s2n_setup_crypto_random_engine(&s2n_test_openssl_rand_method));
    return 0;
}
