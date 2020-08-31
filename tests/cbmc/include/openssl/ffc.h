/*
 * Changes to OpenSSL version 1.1.1.
 * Copyright Amazon.com, Inc. All Rights Reserved.
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
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

#include <openssl/bn.h>

#ifndef OSSL_INTERNAL_FFC_H
#    define OSSL_INTERNAL_FFC_H

typedef struct ffc_params_st {
    /* Primes */
    BIGNUM *p;
    BIGNUM *q;
    /* Generator */
    BIGNUM *g;
    /* DH X9.42 Optional Subgroup factor j >= 2 where p = j * q + 1 */
    BIGNUM *j;

    /* Required for FIPS186_4 validation of p, q and optionally canonical g */
    unsigned char *seed;
    /* If this value is zero the hash size is used as the seed length */
    size_t seedlen;
    /* Required for FIPS186_4 validation of p and q */
    int pcounter;
    int nid; /* The identity of a named group */

    /*
     * Required for FIPS186_4 generation & validation of canonical g.
     * It uses unverifiable g if this value is -1.
     */
    int gindex;
    int h; /* loop counter for unverifiable g */
} FFC_PARAMS;

#endif
