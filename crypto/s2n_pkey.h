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

#pragma once

#include "crypto/s2n_ecdsa.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_rsa_pss.h"

#include "utils/s2n_blob.h"

/* Public/Private Key Type */
typedef enum {
    S2N_PKEY_TYPE_UNKNOWN = -1,
    S2N_PKEY_TYPE_RSA = 0,
    S2N_PKEY_TYPE_ECDSA,
    S2N_PKEY_TYPE_RSA_PSS,
    S2N_PKEY_TYPE_SENTINEL
} s2n_pkey_type;

/* Structure that models a public or private key and type-specific operations */
struct s2n_pkey {
    union {
        struct s2n_rsa_key rsa_key;
        struct s2n_ecdsa_key ecdsa_key;
#if RSA_PSS_SUPPORTED
        struct s2n_rsa_pss_key rsa_pss_key;
#endif
    } key;

    int (*size)(const struct s2n_pkey *key);
    int (*sign)(const struct s2n_pkey *priv_key, struct s2n_hash_state *digest, struct s2n_blob *signature);
    int (*verify)(const struct s2n_pkey *pub_key, struct s2n_hash_state *digest, struct s2n_blob *signature);
    int (*encrypt)(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
    int (*decrypt)(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
    int (*match)(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key); 
    int (*free)(struct s2n_pkey *key);
    int (*check_key)(const struct s2n_pkey *key);
};

extern int s2n_pkey_zero_init(struct s2n_pkey *pkey);
extern int s2n_pkey_setup_for_type(struct s2n_pkey *pkey, s2n_pkey_type pkey_type);
extern int s2n_pkey_check_key_exists(const struct s2n_pkey *pkey);

extern int s2n_pkey_size(const struct s2n_pkey *pkey);
extern int s2n_pkey_sign(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_pkey_verify(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_pkey_encrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_pkey_decrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_pkey_match(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key);
extern int s2n_pkey_free(struct s2n_pkey *pkey);

extern int s2n_asn1der_to_private_key(struct s2n_pkey *priv_key, struct s2n_blob *asn1der);
extern int s2n_asn1der_to_public_key_and_type(struct s2n_pkey *pub_key, s2n_pkey_type *pkey_type, struct s2n_blob *asn1der);
