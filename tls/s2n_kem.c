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

int s2n_kem_generate_keypair(struct s2n_kem_keypair *kem_keys)
{
    notnull_check(kem_keys);
    const struct s2n_kem *kem = kem_keys->negotiated_kem;
    notnull_check(kem->generate_keypair);

    eq_check(kem_keys->public_key.size, kem->public_key_length);
    notnull_check(kem_keys->public_key.data);

    /* The private key is needed for client_key_recv and must be saved */
    GUARD(s2n_alloc(&kem_keys->private_key, kem->private_key_length));

    GUARD(kem->generate_keypair(kem_keys->public_key.data, kem_keys->private_key.data));
    return 0;
}

int s2n_kem_encapsulate(const struct s2n_kem_keypair *kem_keys, struct s2n_blob *shared_secret,
                        struct s2n_blob *ciphertext)
{
    notnull_check(kem_keys);
    const struct s2n_kem *kem = kem_keys->negotiated_kem;
    notnull_check(kem->encapsulate);

    eq_check(kem_keys->public_key.size, kem->public_key_length);
    notnull_check(kem_keys->public_key.data);

    eq_check(ciphertext->size, kem->ciphertext_length);
    notnull_check(ciphertext->data);

    GUARD(s2n_alloc(shared_secret, kem->shared_secret_key_length));

    GUARD(kem->encapsulate(ciphertext->data, shared_secret->data, kem_keys->public_key.data));
    return 0;
}

int s2n_kem_decapsulate(const struct s2n_kem_keypair *kem_keys, struct s2n_blob *shared_secret,
                        const struct s2n_blob *ciphertext)
{
    notnull_check(kem_keys);
    const struct s2n_kem *kem = kem_keys->negotiated_kem;
    notnull_check(kem->decapsulate);

    eq_check(kem_keys->private_key.size, kem->private_key_length);
    notnull_check(kem_keys->private_key.data);

    eq_check(ciphertext->size, kem->ciphertext_length);
    notnull_check(ciphertext->data);

    GUARD(s2n_alloc(shared_secret, kem_keys->negotiated_kem->shared_secret_key_length));

    GUARD(kem->decapsulate(shared_secret->data, ciphertext->data, kem_keys->private_key.data));
    return 0;
}

int s2n_kem_find_supported_kem(const struct s2n_blob *client_kem_ids, const struct s2n_kem *server_supported_kems,
                               const int num_server_supported_kems, const struct s2n_kem **matching_kem)
{
    for (int i = 0; i < num_server_supported_kems; i++) {
        const struct s2n_kem candidate_server_kem_name = server_supported_kems[i];
        for (int j = 0; j < client_kem_ids->size; j++) {
            const kem_extension_size candidate_client_kem_id = client_kem_ids->data[j];

            if (candidate_server_kem_name.kem_extension_id == candidate_client_kem_id) {
                *matching_kem = &server_supported_kems[i];
                return 0;
            }
        }
    }

    /* Nothing found */
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
    return 0;
}

int s2n_kem_free(struct s2n_kem_keypair *kem_keys)
{
    if (kem_keys != NULL){
        GUARD(s2n_blob_zero(&kem_keys->private_key));
        if (kem_keys->private_key.allocated) {
            GUARD(s2n_free(&kem_keys->private_key));
        }
        if (kem_keys->public_key.allocated) {
            GUARD(s2n_free(&kem_keys->public_key));
        }
    }
    return 0;
}
