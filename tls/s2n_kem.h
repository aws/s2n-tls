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
#include "tls/s2n_kem_params.h"

#define KEM_EXTENSION_BYTES 1
#define KEM_PUBLIC_KEY_BYTES 2

struct s2n_kem {
    uint8_t kem_extension_id;
    const uint16_t publicKeySize;
    const uint16_t privateKeySize;
    const uint16_t sharedSecretKeySize;
    const uint16_t ciphertextSize;
    int (*generate_keypair)(unsigned char *public_key, unsigned char *private_key);
    int (*encrypt)(unsigned char *ciphertext, unsigned char *shared_secret,  const unsigned char *public_key);
    int (*decrypt)(unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key);
};

extern int s2n_kem_generate_key_pair(const struct s2n_kem *kem, struct s2n_kem_params *kem_params);

extern int s2n_kem_generate_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *kem_params,
                                          struct s2n_blob *shared_secret, struct s2n_blob *ciphertext);

extern int s2n_kem_decrypt_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *kem_params,
                                         struct s2n_blob *shared_secret, struct s2n_blob *ciphertext);

extern int s2n_kem_find_supported_named_kem(struct s2n_blob *client_kem_names, const struct s2n_kem supported_kems[], const int num_supported_kems,
                                     const struct s2n_kem **matching_kem);

extern int s2n_kem_wipe_keys(struct s2n_kem_params *kem_params);
