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

#include <openssl/crypto.h>

#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"

#include "tls/s2n_prf.h"

/* Global declared in crypto/s2n_hash.h */
const struct s2n_hash *s2n_hash;
/* Global declared in tls/s2n_prf.h */
const struct s2n_p_hash_hmac *s2n_p_hash_hmac;

static int s2n_fips_mode = 0;

int s2n_fips_init()
{
#ifdef OPENSSL_FIPS
    /* FIPS mode can be entered only if OPENSSL_FIPS is defined */
    if (FIPS_mode()) {
        s2n_fips_mode = 1;
    } else {
        s2n_fips_mode = 0;
    }
#endif

    if (s2n_is_in_fips_mode()) {
        /* When in FIPS mode, the EVP API's must be used for hashes and the p_hash HMAC */
        s2n_hash = &s2n_evp_hash;
        s2n_p_hash_hmac = &s2n_evp_hmac;
    } else {
        s2n_hash = &s2n_low_level_hash;
        s2n_p_hash_hmac = &s2n_hmac;
    }

    return 0;
}

int s2n_fips_cleanup()
{
    s2n_fips_mode = 0;

    return 0;
}

/* Return 1 if FIPS mode is enabled, 0 otherwise. FIPS mode must be enabled prior to calling s2n_init(). */
int s2n_is_in_fips_mode()
{
    if (s2n_fips_mode) {
        return 1;
    } else {
        return 0;
    }
}
