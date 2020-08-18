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

#ifndef HEADER_ASN1_H
#define HEADER_ASN1_H

#include <openssl/ossl_typ.h>

void          ASN1_STRING_clear_free(ASN1_STRING *a);
BIGNUM *      ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, unsigned char **ppin, long length);
int           i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **ppout);

#endif /* HEADER_ASN1_H */
