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

#include "tls/s2n_certificate_keys.h"

#include <openssl/objects.h>

const struct s2n_certificate_key s2n_rsa_rsae_1024 = {
    .public_key_libcrypto_nid = NID_rsaEncryption,
    .bits = 1024,
};

const struct s2n_certificate_key s2n_rsa_rsae_2048 = {
    .public_key_libcrypto_nid = NID_rsaEncryption,
    .bits = 2048,
};

const struct s2n_certificate_key s2n_rsa_rsae_3072 = {
    .public_key_libcrypto_nid = NID_rsaEncryption,
    .bits = 3072,
};

const struct s2n_certificate_key s2n_rsa_rsae_4096 = {
    .public_key_libcrypto_nid = NID_rsaEncryption,
    .bits = 4096,
};

const struct s2n_certificate_key s2n_rsa_pss_1024 = {
    .public_key_libcrypto_nid = NID_rsassaPss,
    .bits = 1024,
};

const struct s2n_certificate_key s2n_rsa_pss_2048 = {
    .public_key_libcrypto_nid = NID_rsassaPss,
    .bits = 2048,
};

const struct s2n_certificate_key s2n_rsa_pss_3072 = {
    .public_key_libcrypto_nid = NID_rsassaPss,
    .bits = 3072,
};

const struct s2n_certificate_key s2n_rsa_pss_4096 = {
    .public_key_libcrypto_nid = NID_rsassaPss,
    .bits = 4096,
};

const struct s2n_certificate_key s2n_ec_p256 = {
    .public_key_libcrypto_nid = NID_X9_62_prime256v1,
    .bits = 256,
};

const struct s2n_certificate_key s2n_ec_p384 = {
    .public_key_libcrypto_nid = NID_secp384r1,
    .bits = 384,
};

const struct s2n_certificate_key s2n_ec_p521 = {
    .public_key_libcrypto_nid = NID_secp521r1,
    .bits = 521,
};
