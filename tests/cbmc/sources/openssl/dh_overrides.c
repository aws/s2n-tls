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

#include <cbmc_proof/nondet.h>
#include <openssl/dh.h>
#include <openssl/ossl_typ.h>

int DH_size(const DH *dh)
{
    return nondet_int();
}

void DH_free(DH *dh)
{
    return;
}

DH *d2i_DHparams(DH **a,const unsigned char **pp, long length)
{
    DH *dummy_dh;
    if(nondet_bool() && *pp != NULL) {
        *pp = *pp + length;
    }
    return dummy_dh;
}
