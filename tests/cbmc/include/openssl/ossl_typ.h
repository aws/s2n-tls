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

#ifndef HEADER_OPENSSL_TYPES_H
#define HEADER_OPENSSL_TYPES_H

#ifdef NO_ASN1_TYPEDEFS
#    define ASN1_INTEGER ASN1_STRING
#else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_STRING;
#endif

#ifdef BIGNUM
#    undef BIGNUM
#endif
typedef struct bio_st    BIO;
typedef struct bignum_st BIGNUM;

typedef struct dh_st     DH;
typedef struct dh_method DH_METHOD;

typedef struct ec_key_st EC_KEY;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct hmac_ctx_st     HMAC_CTX;

typedef struct evp_cipher_st     EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_st         EVP_MD;
typedef struct evp_md_ctx_st     EVP_MD_CTX;
typedef struct evp_pkey_st       EVP_PKEY;

typedef struct engine_st ENGINE;

/* This empty definition is required for BIGNUM to function properly in CBMC. */
struct bignum_st {
};

#endif
