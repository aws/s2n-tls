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

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_kem.h"
#include "tls/extensions/s2n_key_share.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "pq-crypto/s2n_pq.h"

/* The KEM IDs and names come from https://tools.ietf.org/html/draft-campagna-tls-bike-sike-hybrid */
const struct s2n_kem s2n_bike1_l1_r1 = {
        .name = "BIKE1r1-Level1",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1,
        .public_key_length = BIKE1_L1_R1_PUBLIC_KEY_BYTES,
        .private_key_length = BIKE1_L1_R1_SECRET_KEY_BYTES,
        .shared_secret_key_length = BIKE1_L1_R1_SHARED_SECRET_BYTES,
        .ciphertext_length = BIKE1_L1_R1_CIPHERTEXT_BYTES,
        .generate_keypair = &BIKE1_L1_R1_crypto_kem_keypair,
        .encapsulate = &BIKE1_L1_R1_crypto_kem_enc,
        .decapsulate = &BIKE1_L1_R1_crypto_kem_dec,
};

const struct s2n_kem s2n_bike1_l1_r2 = {
        .name = "BIKE1r2-Level1",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2,
        .public_key_length = BIKE1_L1_R2_PUBLIC_KEY_BYTES,
        .private_key_length = BIKE1_L1_R2_SECRET_KEY_BYTES,
        .shared_secret_key_length = BIKE1_L1_R2_SHARED_SECRET_BYTES,
        .ciphertext_length = BIKE1_L1_R2_CIPHERTEXT_BYTES,
        .generate_keypair = &BIKE1_L1_R2_crypto_kem_keypair,
        .encapsulate = &BIKE1_L1_R2_crypto_kem_enc,
        .decapsulate = &BIKE1_L1_R2_crypto_kem_dec,
};

const struct s2n_kem s2n_bike_l1_r3 = {
        .name = "BIKEr3-Level1",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R3,
        .public_key_length = BIKE_L1_R3_PUBLIC_KEY_BYTES,
        .private_key_length = BIKE_L1_R3_SECRET_KEY_BYTES,
        .shared_secret_key_length = BIKE_L1_R3_SHARED_SECRET_BYTES,
        .ciphertext_length = BIKE_L1_R3_CIPHERTEXT_BYTES,
        .generate_keypair = &BIKE_L1_R3_crypto_kem_keypair,
        .encapsulate = &BIKE_L1_R3_crypto_kem_enc,
        .decapsulate = &BIKE_L1_R3_crypto_kem_dec,
};

const struct s2n_kem s2n_sike_p503_r1 = {
        .name = "SIKEp503r1-KEM",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1,
        .public_key_length = SIKE_P503_R1_PUBLIC_KEY_BYTES,
        .private_key_length = SIKE_P503_R1_SECRET_KEY_BYTES,
        .shared_secret_key_length = SIKE_P503_R1_SHARED_SECRET_BYTES,
        .ciphertext_length = SIKE_P503_R1_CIPHERTEXT_BYTES,
        .generate_keypair = &SIKE_P503_r1_crypto_kem_keypair,
        .encapsulate = &SIKE_P503_r1_crypto_kem_enc,
        .decapsulate = &SIKE_P503_r1_crypto_kem_dec,
};

const struct s2n_kem s2n_sike_p434_r2 = {
        .name = "SIKEp434r2-KEM",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2,
        .public_key_length = SIKE_P434_R2_PUBLIC_KEY_BYTES,
        .private_key_length = SIKE_P434_R2_SECRET_KEY_BYTES,
        .shared_secret_key_length = SIKE_P434_R2_SHARED_SECRET_BYTES,
        .ciphertext_length = SIKE_P434_R2_CIPHERTEXT_BYTES,
        .generate_keypair = &SIKE_P434_r2_crypto_kem_keypair,
        .encapsulate = &SIKE_P434_r2_crypto_kem_enc,
        .decapsulate = &SIKE_P434_r2_crypto_kem_dec,
};

const struct s2n_kem s2n_kyber_512_r2 = {
        .name = "kyber512r2",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R2,
        .public_key_length = KYBER_512_R2_PUBLIC_KEY_BYTES,
        .private_key_length = KYBER_512_R2_SECRET_KEY_BYTES,
        .shared_secret_key_length = KYBER_512_R2_SHARED_SECRET_BYTES,
        .ciphertext_length = KYBER_512_R2_CIPHERTEXT_BYTES,
        .generate_keypair = &kyber_512_r2_crypto_kem_keypair,
        .encapsulate = &kyber_512_r2_crypto_kem_enc,
        .decapsulate = &kyber_512_r2_crypto_kem_dec,
};

const struct s2n_kem s2n_kyber_512_90s_r2 = {
        .name = "kyber51290sr2",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_KYBER_512_90S_R2,
        .public_key_length = KYBER_512_R2_PUBLIC_KEY_BYTES,
        .private_key_length = KYBER_512_R2_SECRET_KEY_BYTES,
        .shared_secret_key_length = KYBER_512_R2_SHARED_SECRET_BYTES,
        .ciphertext_length = KYBER_512_R2_CIPHERTEXT_BYTES,
        .generate_keypair = &kyber_512_90s_r2_crypto_kem_keypair,
        .encapsulate = &kyber_512_90s_r2_crypto_kem_enc,
        .decapsulate = &kyber_512_90s_r2_crypto_kem_dec,
};

const struct s2n_kem s2n_kyber_512_r3 = {
        .name = "kyber512r3",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R3,
        .public_key_length = S2N_KYBER_512_R3_PUBLIC_KEY_BYTES,
        .private_key_length = S2N_KYBER_512_R3_SECRET_KEY_BYTES,
        .shared_secret_key_length = S2N_KYBER_512_R3_SHARED_SECRET_BYTES,
        .ciphertext_length = S2N_KYBER_512_R3_CIPHERTEXT_BYTES,
        .generate_keypair = &s2n_kyber_512_r3_crypto_kem_keypair,
        .encapsulate = &s2n_kyber_512_r3_crypto_kem_enc,
        .decapsulate = &s2n_kyber_512_r3_crypto_kem_dec,
};

const struct s2n_kem s2n_sike_p434_r3 = {
        .name = "SIKEp434r3-KEM",
        .kem_extension_id = TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R3,
        .public_key_length = S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES,
        .private_key_length = S2N_SIKE_P434_R3_SECRET_KEY_BYTES,
        .shared_secret_key_length = S2N_SIKE_P434_R3_SHARED_SECRET_BYTES,
        .ciphertext_length = S2N_SIKE_P434_R3_CIPHERTEXT_BYTES,
        .generate_keypair = &s2n_sike_p434_r3_crypto_kem_keypair,
        .encapsulate = &s2n_sike_p434_r3_crypto_kem_enc,
        .decapsulate = &s2n_sike_p434_r3_crypto_kem_dec,
};

/* These lists should be kept up to date with the above KEMs. Order in the lists
 * does not matter. Adding a KEM to these lists will not automatically enable
 * support for the KEM extension - that must be added via the KEM preferences &
 * security policies. These lists are applicable only to PQ-TLS 1.2. */
const struct s2n_kem *bike_kems[] = {
        &s2n_bike1_l1_r1,
        &s2n_bike1_l1_r2,
        &s2n_bike_l1_r3
};

const struct s2n_kem *sike_kems[] = {
        &s2n_sike_p503_r1,
        &s2n_sike_p434_r2,
        &s2n_sike_p434_r3,
};

const struct s2n_kem *kyber_kems[] = {
        &s2n_kyber_512_r2,
        &s2n_kyber_512_90s_r2,
        &s2n_kyber_512_r3,
};

const struct s2n_iana_to_kem kem_mapping[3] = {
        {
            .iana_value = { TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384 },
            .kems = bike_kems,
            .kem_count = s2n_array_len(bike_kems),
        },
        {
            .iana_value = { TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 },
            .kems = sike_kems,
            .kem_count = s2n_array_len(sike_kems),
        },
        {
            .iana_value = { TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 },
            .kems = kyber_kems,
            .kem_count = s2n_array_len(kyber_kems),
        }
};

/* Specific assignments of KEM group IDs and names have not yet been
 * published in an RFC (or draft). There is consensus in the
 * community to use values in the proposed reserved range defined in
 * https://tools.ietf.org/html/draft-stebila-tls-hybrid-design.
 * Values for interoperability are defined in
 * https://docs.google.com/spreadsheets/d/12YarzaNv3XQNLnvDsWLlRKwtZFhRrDdWf36YlzwrPeg/edit#gid=0.
 *
 * The structure of the hybrid share is:
 *    size of ECC key share (2 bytes)
 * || ECC key share (variable bytes)
 * || size of PQ key share (2 bytes)
 * || PQ key share (variable bytes) */
const struct s2n_kem_group s2n_secp256r1_sike_p434_r2 = {
        .name = "secp256r1_sike-p434-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2,
        .client_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + SECP256R1_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + SIKE_P434_R2_PUBLIC_KEY_BYTES),
        .server_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + SECP256R1_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + SIKE_P434_R2_CIPHERTEXT_BYTES),
        .curve = &s2n_ecc_curve_secp256r1,
        .kem = &s2n_sike_p434_r2,
};

const struct s2n_kem_group s2n_secp256r1_bike1_l1_r2 = {
        /* The name string follows the convention in the above google doc */
        .name = "secp256r1_bike-1l1fo-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2,
        .client_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + SECP256R1_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + BIKE1_L1_R2_PUBLIC_KEY_BYTES),
        .server_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + SECP256R1_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + BIKE1_L1_R2_CIPHERTEXT_BYTES),
        .curve = &s2n_ecc_curve_secp256r1,
        .kem = &s2n_bike1_l1_r2,
};

const struct s2n_kem_group s2n_secp256r1_kyber_512_r2 = {
        .name = "secp256r1_kyber-512-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_SECP256R1_KYBER_512_R2,
        .client_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + SECP256R1_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + KYBER_512_R2_PUBLIC_KEY_BYTES),
        .server_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + SECP256R1_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + KYBER_512_R2_CIPHERTEXT_BYTES),
        .curve = &s2n_ecc_curve_secp256r1,
        .kem = &s2n_kyber_512_r2,
};

#if EVP_APIS_SUPPORTED
const struct s2n_kem_group s2n_x25519_sike_p434_r2 = {
        .name = "x25519_sike-p434-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2,
        .client_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + X25519_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + SIKE_P434_R2_PUBLIC_KEY_BYTES),
        .server_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + X25519_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + SIKE_P434_R2_CIPHERTEXT_BYTES),
        .curve = &s2n_ecc_curve_x25519,
        .kem = &s2n_sike_p434_r2,
};

const struct s2n_kem_group s2n_x25519_bike1_l1_r2 = {
        /* The name string follows the convention in the above google doc */
        .name = "x25519_bike-1l1fo-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2,
        .client_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + X25519_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + BIKE1_L1_R2_PUBLIC_KEY_BYTES),
        .server_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + X25519_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + BIKE1_L1_R2_CIPHERTEXT_BYTES),
        .curve = &s2n_ecc_curve_x25519,
        .kem = &s2n_bike1_l1_r2,
};

const struct s2n_kem_group s2n_x25519_kyber_512_r2 = {
        .name = "x25519_kyber-512-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_X25519_KYBER_512_R2,
        .client_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + X25519_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + KYBER_512_R2_PUBLIC_KEY_BYTES),
        .server_share_size = (S2N_SIZE_OF_KEY_SHARE_SIZE + X25519_SHARE_SIZE) +
                (S2N_SIZE_OF_KEY_SHARE_SIZE + KYBER_512_R2_CIPHERTEXT_BYTES),
        .curve = &s2n_ecc_curve_x25519,
        .kem = &s2n_kyber_512_r2,
};
#else
const struct s2n_kem_group s2n_x25519_sike_p434_r2 = { 0 };
const struct s2n_kem_group s2n_x25519_bike1_l1_r2 = { 0 };
const struct s2n_kem_group s2n_x25519_kyber_512_r2 = { 0 };
#endif

/* Helper safety macro to call the NIST PQ KEM functions. The NIST
 * functions may return any non-zero value to indicate failure. */
#define GUARD_PQ_AS_RESULT(x)        RESULT_ENSURE((x) == 0, S2N_ERR_PQ_CRYPTO)

S2N_RESULT s2n_kem_generate_keypair(struct s2n_kem_params *kem_params)
{
    RESULT_ENSURE_REF(kem_params);
    RESULT_ENSURE_REF(kem_params->kem);
    const struct s2n_kem *kem = kem_params->kem;
    RESULT_ENSURE_REF(kem->generate_keypair);

    RESULT_ENSURE_REF(kem_params->public_key.data);
    RESULT_ENSURE(kem_params->public_key.size == kem->public_key_length, S2N_ERR_SAFETY);

    /* Need to save the private key for decapsulation */
    RESULT_GUARD_POSIX(s2n_realloc(&kem_params->private_key, kem->private_key_length));

    GUARD_PQ_AS_RESULT(kem->generate_keypair(kem_params->public_key.data, kem_params->private_key.data));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kem_encapsulate(struct s2n_kem_params *kem_params, struct s2n_blob *ciphertext)
{
    RESULT_ENSURE_REF(kem_params);
    RESULT_ENSURE_REF(kem_params->kem);
    const struct s2n_kem *kem = kem_params->kem;
    RESULT_ENSURE_REF(kem->encapsulate);

    RESULT_ENSURE(kem_params->public_key.size == kem->public_key_length, S2N_ERR_SAFETY);
    RESULT_ENSURE_REF(kem_params->public_key.data);

    RESULT_ENSURE_REF(ciphertext);
    RESULT_ENSURE_REF(ciphertext->data);
    RESULT_ENSURE(ciphertext->size == kem->ciphertext_length, S2N_ERR_SAFETY);

    /* Need to save the shared secret for key derivation */
    RESULT_GUARD_POSIX(s2n_alloc(&(kem_params->shared_secret), kem->shared_secret_key_length));

    GUARD_PQ_AS_RESULT(kem->encapsulate(ciphertext->data, kem_params->shared_secret.data, kem_params->public_key.data));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kem_decapsulate(struct s2n_kem_params *kem_params, const struct s2n_blob *ciphertext)
{
    RESULT_ENSURE_REF(kem_params);
    RESULT_ENSURE_REF(kem_params->kem);
    const struct s2n_kem *kem = kem_params->kem;
    RESULT_ENSURE_REF(kem->decapsulate);

    RESULT_ENSURE(kem_params->private_key.size == kem->private_key_length, S2N_ERR_SAFETY);
    RESULT_ENSURE_REF(kem_params->private_key.data);

    RESULT_ENSURE_REF(ciphertext);
    RESULT_ENSURE_REF(ciphertext->data);
    RESULT_ENSURE(ciphertext->size == kem->ciphertext_length, S2N_ERR_SAFETY);

    /* Need to save the shared secret for key derivation */
    RESULT_GUARD_POSIX(s2n_alloc(&(kem_params->shared_secret), kem->shared_secret_key_length));

    GUARD_PQ_AS_RESULT(kem->decapsulate(kem_params->shared_secret.data, ciphertext->data, kem_params->private_key.data));
    return S2N_RESULT_OK;
}

static int s2n_kem_check_kem_compatibility(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_kem *candidate_kem,
        uint8_t *kem_is_compatible) {
    const struct s2n_iana_to_kem *compatible_kems = NULL;
    POSIX_GUARD(s2n_cipher_suite_to_kem(iana_value, &compatible_kems));

    for (uint8_t i = 0; i < compatible_kems->kem_count; i++) {
        if (candidate_kem->kem_extension_id == compatible_kems->kems[i]->kem_extension_id) {
            *kem_is_compatible = 1;
            return S2N_SUCCESS;
        }
    }

    *kem_is_compatible = 0;
    return S2N_SUCCESS;
}

int s2n_choose_kem_with_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], struct s2n_blob *client_kem_ids,
        const struct s2n_kem *server_kem_pref_list[], const uint8_t num_server_supported_kems, const struct s2n_kem **chosen_kem) {
    struct s2n_stuffer client_kem_ids_stuffer = {0};
    POSIX_GUARD(s2n_stuffer_init(&client_kem_ids_stuffer, client_kem_ids));
    POSIX_GUARD(s2n_stuffer_write(&client_kem_ids_stuffer, client_kem_ids));

    /* Each KEM ID is 2 bytes */
    uint8_t num_client_candidate_kems = client_kem_ids->size / 2;

    for (uint8_t i = 0; i < num_server_supported_kems; i++) {
        const struct s2n_kem *candidate_server_kem = (server_kem_pref_list[i]);

        uint8_t server_kem_is_compatible = 0;
        POSIX_GUARD(s2n_kem_check_kem_compatibility(iana_value, candidate_server_kem, &server_kem_is_compatible));

        if (!server_kem_is_compatible) {
            continue;
        }

        for (uint8_t j = 0; j < num_client_candidate_kems; j++) {
            kem_extension_size candidate_client_kem_id;
            POSIX_GUARD(s2n_stuffer_read_uint16(&client_kem_ids_stuffer, &candidate_client_kem_id));

            if (candidate_server_kem->kem_extension_id == candidate_client_kem_id) {
                *chosen_kem = candidate_server_kem;
                return S2N_SUCCESS;
            }
        }
        POSIX_GUARD(s2n_stuffer_reread(&client_kem_ids_stuffer));
    }

    /* Client and server did not propose any mutually supported KEMs compatible with the ciphersuite */
    POSIX_BAIL(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_choose_kem_without_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_kem *server_kem_pref_list[],
        const uint8_t num_server_supported_kems, const struct s2n_kem **chosen_kem) {
    for (uint8_t i = 0; i < num_server_supported_kems; i++) {
        uint8_t kem_is_compatible = 0;
        POSIX_GUARD(s2n_kem_check_kem_compatibility(iana_value, server_kem_pref_list[i], &kem_is_compatible));
        if (kem_is_compatible) {
            *chosen_kem = server_kem_pref_list[i];
            return S2N_SUCCESS;
        }
    }

    /* The server preference list did not contain any KEM extensions compatible with the ciphersuite */
    POSIX_BAIL(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_kem_free(struct s2n_kem_params *kem_params)
{
    if (kem_params != NULL) {
        POSIX_GUARD(s2n_blob_zeroize_free(&kem_params->private_key));
        POSIX_GUARD(s2n_blob_zeroize_free(&kem_params->public_key));
        POSIX_GUARD(s2n_blob_zeroize_free(&kem_params->shared_secret));
    }
    return S2N_SUCCESS;
}

int s2n_kem_group_free(struct s2n_kem_group_params *kem_group_params) {
    if (kem_group_params != NULL) {
        POSIX_GUARD(s2n_kem_free(&kem_group_params->kem_params));
        POSIX_GUARD(s2n_ecc_evp_params_free(&kem_group_params->ecc_params));
    }
    return S2N_SUCCESS;
}

int s2n_cipher_suite_to_kem(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_iana_to_kem **compatible_params) {
    for (int i = 0; i < s2n_array_len(kem_mapping); i++) {
        const struct s2n_iana_to_kem *candidate = &kem_mapping[i];
        if (memcmp(iana_value, candidate->iana_value, S2N_TLS_CIPHER_SUITE_LEN) == 0) {
            *compatible_params = candidate;
            return S2N_SUCCESS;
        }
    }
    POSIX_BAIL(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_get_kem_from_extension_id(kem_extension_size kem_id, const struct s2n_kem **kem) {
    for (int i = 0; i < s2n_array_len(kem_mapping); i++) {
        const struct s2n_iana_to_kem *iana_to_kem = &kem_mapping[i];

        for (int j = 0; j < iana_to_kem->kem_count; j++) {
            const struct s2n_kem *candidate_kem = iana_to_kem->kems[j];
            if (candidate_kem->kem_extension_id == kem_id) {
                *kem = candidate_kem;
                return S2N_SUCCESS;
            }
        }
    }

    POSIX_BAIL(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_kem_send_public_key(struct s2n_stuffer *out, struct s2n_kem_params *kem_params) {
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);

    const struct s2n_kem *kem = kem_params->kem;

    POSIX_GUARD(s2n_stuffer_write_uint16(out, kem->public_key_length));

    /* We don't need to store the public key after sending it.
     * We write it directly to *out. */
    kem_params->public_key.data = s2n_stuffer_raw_write(out, kem->public_key_length);
    POSIX_ENSURE_REF(kem_params->public_key.data);
    kem_params->public_key.size = kem->public_key_length;

    /* Saves the private key in kem_params */
    POSIX_GUARD_RESULT(s2n_kem_generate_keypair(kem_params));

    /* After using s2n_stuffer_raw_write() above to write the public
     * key to the stuffer, we want to ensure that kem_params->public_key.data
     * does not continue to point at *out, else we may unexpectedly
     * overwrite part of the stuffer when s2n_kem_free() is called. */
    kem_params->public_key.data = NULL;
    kem_params->public_key.size = 0;

    return S2N_SUCCESS;
}

int s2n_kem_recv_public_key(struct s2n_stuffer *in, struct s2n_kem_params *kem_params) {
    POSIX_ENSURE_REF(in);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);

    const struct s2n_kem *kem = kem_params->kem;
    kem_public_key_size public_key_length;

    POSIX_GUARD(s2n_stuffer_read_uint16(in, &public_key_length));
    S2N_ERROR_IF(public_key_length != kem->public_key_length, S2N_ERR_BAD_MESSAGE);

    /* Alloc memory for the public key; the peer receiving it will need it
     * later during the handshake to encapsulate the shared secret. */
    POSIX_GUARD(s2n_alloc(&(kem_params->public_key), public_key_length));
    POSIX_GUARD(s2n_stuffer_read_bytes(in, kem_params->public_key.data, public_key_length));

    return S2N_SUCCESS;
}

int s2n_kem_send_ciphertext(struct s2n_stuffer *out, struct s2n_kem_params *kem_params) {
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);
    POSIX_ENSURE_REF(kem_params->public_key.data);

    const struct s2n_kem *kem = kem_params->kem;

    POSIX_GUARD(s2n_stuffer_write_uint16(out, kem->ciphertext_length));

    /* Ciphertext will get written to *out */
    struct s2n_blob ciphertext = {.data = s2n_stuffer_raw_write(out, kem->ciphertext_length), .size = kem->ciphertext_length};
    POSIX_ENSURE_REF(ciphertext.data);

    /* Saves the shared secret in kem_params */
    POSIX_GUARD_RESULT(s2n_kem_encapsulate(kem_params, &ciphertext));

    return S2N_SUCCESS;
}

int s2n_kem_recv_ciphertext(struct s2n_stuffer *in, struct s2n_kem_params *kem_params) {
    POSIX_ENSURE_REF(in);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);
    POSIX_ENSURE_REF(kem_params->private_key.data);

    const struct s2n_kem *kem = kem_params->kem;
    kem_ciphertext_key_size ciphertext_length;

    POSIX_GUARD(s2n_stuffer_read_uint16(in, &ciphertext_length));
    S2N_ERROR_IF(ciphertext_length != kem->ciphertext_length, S2N_ERR_BAD_MESSAGE);

    const struct s2n_blob ciphertext = {.data = s2n_stuffer_raw_read(in, ciphertext_length), .size = ciphertext_length};
    POSIX_ENSURE_REF(ciphertext.data);

    /* Saves the shared secret in kem_params */
    POSIX_GUARD_RESULT(s2n_kem_decapsulate(kem_params, &ciphertext));

    return S2N_SUCCESS;
}

#if defined(S2N_NO_PQ)
/* If S2N_NO_PQ was defined at compile time, the PQ KEM code will have been entirely excluded
 * from compilation. We define stubs of these functions here to error if they are called. */
/* sikep503r1 */
int SIKE_P503_r1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int SIKE_P503_r1_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN  const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int SIKE_P503_r1_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* sikep434r2 */
int SIKE_P434_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int SIKE_P434_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int SIKE_P434_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* bike1l1r1 */
int BIKE1_L1_R1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int BIKE1_L1_R1_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int BIKE1_L1_R1_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* bike1l1r2*/
int BIKE1_L1_R2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int BIKE1_L1_R2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int BIKE1_L1_R2_crypto_kem_dec(OUT unsigned char * ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* bike1l1r3*/
int BIKE_L1_R3_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int BIKE_L1_R3_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int BIKE_L1_R3_crypto_kem_dec(OUT unsigned char * ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* kyber512r2 */
int kyber_512_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int kyber_512_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int kyber_512_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* kyber512r2 90's version*/
int kyber_512_90s_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int kyber_512_90s_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int kyber_512_90s_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* kyber512r3 */
int s2n_kyber_512_r3_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int s2n_kyber_512_r3_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int s2n_kyber_512_r3_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
/* sikep434r3 */
int s2n_sike_p434_r3_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int s2n_sike_p434_r3_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
int s2n_sike_p434_r3_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk) { POSIX_BAIL(S2N_ERR_UNIMPLEMENTED); }
#endif
