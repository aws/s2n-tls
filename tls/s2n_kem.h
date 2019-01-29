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
#include "utils/s2n_blob.h"

typedef uint8_t kem_extension_size;
typedef uint16_t kem_public_key_size;
typedef uint16_t kem_private_key_size;
typedef uint16_t kem_shared_secret_size;
typedef uint16_t kem_ciphertext_key_size;

struct s2n_kem {
    kem_extension_size kem_extension_id;
    const kem_public_key_size public_key_length;
    const kem_private_key_size private_key_length;
    const kem_shared_secret_size shared_secret_key_length;
    const kem_ciphertext_key_size ciphertext_length;
    int (*generate_keypair)(unsigned char *public_key, unsigned char *private_key);
    int (*encapsulate)(unsigned char *ciphertext, unsigned char *shared_secret,  const unsigned char *public_key);
    int (*decapsulate)(unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key);
};

struct s2n_kem_params {
    const struct s2n_kem *negotiated_kem;
    struct s2n_blob public_key;
    struct s2n_blob private_key;
};

extern int s2n_kem_generate_keypair(struct s2n_kem_params *kem_params);

extern int s2n_kem_encapsulate(const struct s2n_kem_params *kem_params, struct s2n_blob *shared_secret,
                               struct s2n_blob *ciphertext);

extern int s2n_kem_decapsulate(const struct s2n_kem_params *kem_params, struct s2n_blob *shared_secret,
                               const struct s2n_blob *ciphertext);

extern int s2n_kem_find_supported_kem(struct s2n_blob *client_kem_names, const struct s2n_kem *supported_kems,
                                      const int num_supported_kems, const struct s2n_kem **matching_kem);

extern int s2n_kem_wipe_keys(struct s2n_kem_params *kem_params);
