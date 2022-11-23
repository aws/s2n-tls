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

#pragma once

#include "api/s2n.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_rsa.h"
#include "utils/s2n_blob.h"

/* Check for libcrypto 1.1 for RSA PSS Signing and EV_Key usage */
#if (S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 1) || defined(OPENSSL_IS_AWSLC)) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL)
    #define RSA_PSS_SIGNING_SUPPORTED 1
#else
    #define RSA_PSS_SIGNING_SUPPORTED 0
#endif

int s2n_rsa_pkcs1v15_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature);
int s2n_rsa_pkcs1v15_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature);

int s2n_rsa_pss_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature_out);
int s2n_rsa_pss_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature_in);

int s2n_is_rsa_pss_signing_supported();
