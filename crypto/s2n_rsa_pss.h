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

#pragma once

#include <stdint.h>
#include <s2n.h>
#include <openssl/evp.h>

#include "crypto/s2n_hash.h"
#include "utils/s2n_blob.h"

/* OpenSSL 1.1.1d  10 Sep 2019 is broken, so disable on that version. For further info see: crypto/evp/p_lib.c:469
 *
 * This feature requires this Openssl commit for Openssl 1.1.x versions: openssl/openssl@4088b92
 */
#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 1) && !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER != 0x1010104fL
#define RSA_PSS_SUPPORTED 1
#define RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE    32
#define RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE      256
#else
#define RSA_PSS_SUPPORTED 0
#endif

/* Forward declaration to avoid the circular dependency with s2n_pkey.h */
struct s2n_pkey;

#if RSA_PSS_SUPPORTED

struct s2n_rsa_pss_key {
    EVP_PKEY *pkey;
};

extern int s2n_rsa_pss_pkey_init(struct s2n_pkey *pkey);
extern int s2n_evp_pkey_to_rsa_pss_public_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey);
extern int s2n_evp_pkey_to_rsa_pss_private_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey);

extern int s2n_rsa_pss_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature_out);
extern int s2n_rsa_pss_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature_in);

#endif
