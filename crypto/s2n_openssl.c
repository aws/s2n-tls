/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_openssl.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND

int s2n_openssl_compat_rand(unsigned char *buf, int num)
{
    struct s2n_blob out = {.data = buf,.size = num };

    if (s2n_get_private_random_data(&out) < 0) {
        return 0;
    }
    return 1;
}

int s2n_openssl_compat_status(void)
{
    return 1;
}

int s2n_openssl_compat_init(ENGINE * unused)
{
    return 1;
}

RAND_METHOD s2n_openssl_rand_method = {
    .seed = NULL,
    .bytes = s2n_openssl_compat_rand,
    .cleanup = NULL,
    .add = NULL,
    .pseudorand = s2n_openssl_compat_rand,
    .status = s2n_openssl_compat_status
};

int s2n_setup_crypto_random_engine(RAND_METHOD *method)
{
    /* Create an engine */
    ENGINE *e = ENGINE_new();
    if (e == NULL ||
        ENGINE_set_id(e, "s2n_rand") != 1 ||
        ENGINE_set_name(e, "s2n entropy generator") != 1 ||
        ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) != 1 ||
        ENGINE_set_init_function(e, s2n_openssl_compat_init) != 1 ||
        ENGINE_set_RAND(e, method) != 1 ||
        ENGINE_add(e) != 1 ||
        ENGINE_free(e) != 1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }

    /* Use that engine for rand() */
    e = ENGINE_by_id("s2n_rand");
    S2N_ERROR_IF(e == NULL || ENGINE_init(e) != 1 || ENGINE_set_default(e, ENGINE_METHOD_RAND) != 1 || ENGINE_free(e) != 1, S2N_ERR_OPEN_RANDOM);
    return 0;
}
#endif
