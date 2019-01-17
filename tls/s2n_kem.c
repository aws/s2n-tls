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

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_kem.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

int s2n_kem_generate_key_pair(const struct s2n_kem *kem, struct s2n_kem_params *kem_params)
{
    notnull_check(kem->generate_keypair);
    GUARD(s2n_alloc(&kem_params->public_key, kem->publicKeySize));
    GUARD(s2n_alloc(&kem_params->private_key, kem->privateKeySize));
    GUARD(kem->generate_keypair(kem_params->public_key.data, kem_params->private_key.data));
    return 0;
}

int s2n_kem_generate_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *kem_params,
                                   struct s2n_blob *shared_secret, struct s2n_blob *ciphertext)
{
    notnull_check(kem->encrypt);
    GUARD(s2n_alloc(shared_secret, kem->sharedSecretKeySize));
    GUARD(s2n_alloc(ciphertext, kem->ciphertextSize));
    GUARD(kem->encrypt(ciphertext->data, shared_secret->data, kem_params->public_key.data));
    return 0;
}

int s2n_kem_decrypt_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *kem_params,
                                  struct s2n_blob *shared_secret, struct s2n_blob *ciphertext)
{
    notnull_check(kem->decrypt);
    notnull_check(kem_params->private_key.data);
    eq_check(kem->ciphertextSize, ciphertext->size);

    GUARD(s2n_alloc(shared_secret, kem->sharedSecretKeySize));
    GUARD(kem->decrypt(shared_secret->data, ciphertext->data, kem_params->private_key.data));
    return 0;
}

int s2n_kem_find_supported_named_kem(struct s2n_blob *client_kem_names, const struct s2n_kem supported_kems[], const int num_supported_kems,
        const struct s2n_kem **matching_kem)
{
    struct s2n_stuffer kem_name_in = {{0}};

    GUARD(s2n_stuffer_init(&kem_name_in, client_kem_names));
    GUARD(s2n_stuffer_write(&kem_name_in, client_kem_names));
    for (int i = 0; i < num_supported_kems; i++) {
        const struct s2n_kem candidate_server_kem_name = supported_kems[i];
        for (int j = 0; j < client_kem_names->size; j++) {
            uint8_t kem_name;
            GUARD(s2n_stuffer_read_uint8(&kem_name_in, &kem_name));

            if (candidate_server_kem_name.kem_extension_id == kem_name) {
                *matching_kem = supported_kems + i;
                return 0;
            }
        }
        GUARD(s2n_stuffer_reread(&kem_name_in));
    }

    /* Nothing found */
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
    return 0;
}

int s2n_kem_wipe_keys(struct s2n_kem_params *kem_params)
{
    if (kem_params != NULL){
        if (kem_params->private_key.allocated) {
            GUARD(s2n_free(&kem_params->private_key));
        }
        if (kem_params->public_key.allocated) {
            GUARD(s2n_free(&kem_params->public_key));
        }
    }
    return 0;
}
