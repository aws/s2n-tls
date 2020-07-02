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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <time.h>

#include "api/s2n.h"
#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_crypto.h"
#include "utils/s2n_blob.h"



int s2n_pkey_verify(const struct s2n_pkey *key, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature){

    typedef int (*orig_s2n_pkey_verify_func_type)(const struct s2n_pkey *key, s2n_signature_algorithm sig_alg,
            struct s2n_hash_state *digest, struct s2n_blob *signature);
    orig_s2n_pkey_verify_func_type orig_s2n_pkey_verify;
    orig_s2n_pkey_verify = (orig_s2n_pkey_verify_func_type) dlsym(RTLD_NEXT, "s2n_pkey_verify");
    orig_s2n_pkey_verify(key, sig_alg, digest, signature);

    /* Always assume that pkey_verify passes */
    return S2N_SUCCESS;
}
