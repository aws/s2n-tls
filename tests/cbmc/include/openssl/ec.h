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

#ifndef HEADER_EC_H
#define HEADER_EC_H

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>

/** Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
    /** the point is encoded as z||x, where the octet z specifies
     *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_COMPRESSED = 2,
    /** the point is encoded as z||x||y, where z is the octet 0x04  */
    POINT_CONVERSION_UNCOMPRESSED = 4,
    /** the point is encoded as z||x||y, where the octet z specifies
     *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef struct ec_group_st EC_GROUP;

EC_GROUP *    EC_GROUP_new_by_curve_name(int nid);
void          EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form);
const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group);
void          EC_GROUP_free(EC_GROUP *group);

typedef struct ECDSA_SIG_st ECDSA_SIG;

EC_KEY *        EC_KEY_new(void);
int             EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
void            EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);
int             EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
int             EC_KEY_generate_key(EC_KEY *key);
int             EC_KEY_up_ref(EC_KEY *r);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
const BIGNUM *  EC_KEY_get0_private_key(const EC_KEY *key);
int             EC_KEY_generate_key(EC_KEY *key);
void            EC_KEY_free(EC_KEY *key);

EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);
int     i2o_ECPublicKey(EC_KEY *key, unsigned char **out);

void       ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int        ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
void       ECDSA_SIG_free(ECDSA_SIG *sig);
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);
int        i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);

#endif
