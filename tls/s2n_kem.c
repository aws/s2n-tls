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

#include "pq-crypto/bike/bike1_l1_kem.h"
#include "pq-crypto/sike_r1/sike_p503_r1_kem.h"
#include "pq-crypto/sike_r2/sike_p434_r2_kem.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_kem.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

/* The names below come from https://tools.ietf.org/html/draft-campagna-tls-bike-sike-hybrid-02#section-5.1.6 */
const struct s2n_kem s2n_bike_1_level_1_r1 = {
        .name = "BIKE1r1-Level1",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_BIKE1_R1_LEVEL_1,
        .public_key_length = BIKE1_L1_PUBLIC_KEY_BYTES,
        .private_key_length = BIKE1_L1_SECRET_KEY_BYTES,
        .shared_secret_key_length = BIKE1_L1_SHARED_SECRET_BYTES,
        .ciphertext_length = BIKE1_L1_CIPHERTEXT_BYTES,
        .generate_keypair = &BIKE1_L1_crypto_kem_keypair,
        .encapsulate = &BIKE1_L1_crypto_kem_enc,
        .decapsulate = &BIKE1_L1_crypto_kem_dec,
};

const struct s2n_kem s2n_sike_p503_r1 = {
        .name = "SIKEp503r1-KEM",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1_KEM,
        .public_key_length = SIKE_P503_r1_PUBLIC_KEY_BYTES,
        .private_key_length = SIKE_P503_r1_SECRET_KEY_BYTES,
        .shared_secret_key_length = SIKE_P503_r1_SHARED_SECRET_BYTES,
        .ciphertext_length = SIKE_P503_r1_CIPHERTEXT_BYTES,
        .generate_keypair = &SIKE_P503_r1_crypto_kem_keypair,
        .encapsulate = &SIKE_P503_r1_crypto_kem_enc,
        .decapsulate = &SIKE_P503_r1_crypto_kem_dec,
};

const struct s2n_kem s2n_sike_p434_r2 = {
        .name = "SIKEp434r2-KEM",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2_KEM,
        .public_key_length = SIKE_P434_r2_PUBLIC_KEY_BYTES,
        .private_key_length = SIKE_P434_r2_SECRET_KEY_BYTES,
        .shared_secret_key_length = SIKE_P434_r2_SHARED_SECRET_BYTES,
        .ciphertext_length = SIKE_P434_r2_CIPHERTEXT_BYTES,
        .generate_keypair = &SIKE_P434_r2_crypto_kem_keypair,
        .encapsulate = &SIKE_P434_r2_crypto_kem_enc,
        .decapsulate = &SIKE_P434_r2_crypto_kem_dec,
};

const struct s2n_kem *supported_bike_params[] = {
        &s2n_bike_1_level_1_r1,
};

const struct s2n_kem *supported_sike_params[] = {
        &s2n_sike_p503_r1,
};

const struct s2n_iana_to_kem kem_mapping[2] = {
        {
            .iana_value = { TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384 },
            .kems = supported_bike_params,
            .kem_count = s2n_array_len(supported_bike_params),
        },
        {
            .iana_value = { TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 },
            .kems = supported_sike_params,
            .kem_count = s2n_array_len(supported_sike_params),
        }
};

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

int s2n_kem_find_supported_kem(struct s2n_blob *client_kem_ids, const struct s2n_kem *server_kem_pref_list[],
                               const int num_server_supported_kems, const struct s2n_kem **matching_kem)
{
    struct s2n_stuffer client_kems_in = {0};

    GUARD(s2n_stuffer_init(&client_kems_in, client_kem_ids));
    GUARD(s2n_stuffer_write(&client_kems_in, client_kem_ids));

    for (int i = 0; i < num_server_supported_kems; i++) {
        const struct s2n_kem candidate_server_kem_name = *server_kem_pref_list[i];
        for (int j = 0; j < client_kem_ids->size / 2; j++) {
            kem_extension_size candidate_client_kem_id;
            GUARD(s2n_stuffer_read_uint16(&client_kems_in, &candidate_client_kem_id));

            if (candidate_server_kem_name.kem_extension_id == candidate_client_kem_id) {
                *matching_kem = server_kem_pref_list[i];
                return 0;
            }
        }
        GUARD(s2n_stuffer_reread(&client_kems_in));
    }

    /* Nothing found */
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
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

int s2n_cipher_suite_to_kem(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_iana_to_kem **supported_params)
{
    for (int i = 0; i < s2n_array_len(kem_mapping); i++) {
        const struct s2n_iana_to_kem *candidate = &kem_mapping[i];
        if (memcmp(iana_value, candidate->iana_value, S2N_TLS_CIPHER_SUITE_LEN) == 0) {
            *supported_params = candidate;
            return 0;
        }
    }
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}
