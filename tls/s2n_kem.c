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

#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

#if !defined(S2N_NO_PQ)

#include "pq-crypto/bike_r1/bike_r1_kem.h"
#include "pq-crypto/bike_r2/bike_r2_kem.h"
#include "pq-crypto/sike_r1/sike_r1_kem.h"
#include "pq-crypto/sike_r2/sike_r2_kem.h"
#include "pq-crypto/kyber_r2/kyber_r2_kem.h"

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

/* These lists should be kept up to date with the above KEMs. Order in the lists
 * does not matter. Adding a KEM to these lists will not automatically enable
 * support for the KEM extension - that must be added via the cipher preferences.
 * These lists are applicable only to PQ-TLS 1.2. */
const struct s2n_kem *bike_kems[] = {
        &s2n_bike1_l1_r1,
        &s2n_bike1_l1_r2
};
const struct s2n_kem *sike_kems[] = {
        &s2n_sike_p503_r1,
        &s2n_sike_p434_r2,
};

const struct s2n_kem *kyber_kems[] = {
        &s2n_kyber_512_r2,
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
 * https://docs.google.com/spreadsheets/d/12YarzaNv3XQNLnvDsWLlRKwtZFhRrDdWf36YlzwrPeg/edit#gid=0. */
const struct s2n_kem_group s2n_secp256r1_sike_p434_r2 = {
        .name = "secp256r1_sike-p434-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2,
        .curve = &s2n_ecc_curve_secp256r1,
        .kem = &s2n_sike_p434_r2,
};

const struct s2n_kem_group s2n_secp256r1_bike1_l1_r2 = {
        /* The name string follows the convention in the above google doc */
        .name = "secp256r1_bike-1l1fo-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2,
        .curve = &s2n_ecc_curve_secp256r1,
        .kem = &s2n_bike1_l1_r2,
};

#if EVP_APIS_SUPPORTED
const struct s2n_kem_group s2n_x25519_sike_p434_r2 = {
        .name = "x25519_sike-p434-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2,
        .curve = &s2n_ecc_curve_x25519,
        .kem = &s2n_sike_p434_r2,
};

const struct s2n_kem_group s2n_x25519_bike1_l1_r2 = {
        /* The name string follows the convention in the above google doc */
        .name = "x25519_bike-1l1fo-r2",
        .iana_id = TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2,
        .curve = &s2n_ecc_curve_x25519,
        .kem = &s2n_bike1_l1_r2,
};
#else
const struct s2n_kem_group s2n_x25519_sike_p434_r2 = { 0 };
const struct s2n_kem_group s2n_x25519_bike1_l1_r2 = { 0 };
#endif

#else

/* Compiler warns that zero-length arrays are undefined according to the C standard. Instead, a
   single NULL KEM mapping with a 0 count will be detected and treated as 0 length. */
const struct s2n_iana_to_kem kem_mapping[1] = {
        {
            .iana_value = { TLS_NULL_WITH_NULL_NULL },
            .kems = NULL,
            .kem_count = 0,
        }
};

#endif

int s2n_kem_generate_keypair(struct s2n_kem_params *kem_params)
{
    notnull_check(kem_params);
    notnull_check(kem_params->kem);
    const struct s2n_kem *kem = kem_params->kem;
    notnull_check(kem->generate_keypair);

    eq_check(kem_params->public_key.size, kem->public_key_length);
    notnull_check(kem_params->public_key.data);

    /* Need to save the private key for decapsulation */
    GUARD(s2n_alloc(&kem_params->private_key, kem->private_key_length));

    GUARD(kem->generate_keypair(kem_params->public_key.data, kem_params->private_key.data));
    return S2N_SUCCESS;
}

int s2n_kem_encapsulate(struct s2n_kem_params *kem_params, struct s2n_blob *ciphertext)
{
    notnull_check(kem_params);
    notnull_check(kem_params->kem);
    const struct s2n_kem *kem = kem_params->kem;
    notnull_check(kem->encapsulate);

    eq_check(kem_params->public_key.size, kem->public_key_length);
    notnull_check(kem_params->public_key.data);

    eq_check(ciphertext->size, kem->ciphertext_length);
    notnull_check(ciphertext->data);

    /* Need to save the shared secret for key derivation */
    GUARD(s2n_alloc(&(kem_params->shared_secret), kem->shared_secret_key_length));

    GUARD(kem->encapsulate(ciphertext->data, kem_params->shared_secret.data, kem_params->public_key.data));
    return S2N_SUCCESS;
}

int s2n_kem_decapsulate(struct s2n_kem_params *kem_params, const struct s2n_blob *ciphertext)
{
    notnull_check(kem_params);
    notnull_check(kem_params->kem);
    const struct s2n_kem *kem = kem_params->kem;
    notnull_check(kem->decapsulate);

    eq_check(kem_params->private_key.size, kem->private_key_length);
    notnull_check(kem_params->private_key.data);

    eq_check(ciphertext->size, kem->ciphertext_length);
    notnull_check(ciphertext->data);

    /* Need to save the shared secret for key derivation */
    GUARD(s2n_alloc(&(kem_params->shared_secret), kem->shared_secret_key_length));

    GUARD(kem->decapsulate(kem_params->shared_secret.data, ciphertext->data, kem_params->private_key.data));
    return S2N_SUCCESS;
}

static int s2n_kem_check_kem_compatibility(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_kem *candidate_kem,
        uint8_t *kem_is_compatible) {
    const struct s2n_iana_to_kem *compatible_kems = NULL;
    GUARD(s2n_cipher_suite_to_kem(iana_value, &compatible_kems));

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
    GUARD(s2n_stuffer_init(&client_kem_ids_stuffer, client_kem_ids));
    GUARD(s2n_stuffer_write(&client_kem_ids_stuffer, client_kem_ids));

    /* Each KEM ID is 2 bytes */
    uint8_t num_client_candidate_kems = client_kem_ids->size / 2;

    for (uint8_t i = 0; i < num_server_supported_kems; i++) {
        const struct s2n_kem *candidate_server_kem = (server_kem_pref_list[i]);

        uint8_t server_kem_is_compatible = 0;
        GUARD(s2n_kem_check_kem_compatibility(iana_value, candidate_server_kem, &server_kem_is_compatible));

        if (!server_kem_is_compatible) {
            continue;
        }

        for (uint8_t j = 0; j < num_client_candidate_kems; j++) {
            kem_extension_size candidate_client_kem_id;
            GUARD(s2n_stuffer_read_uint16(&client_kem_ids_stuffer, &candidate_client_kem_id));

            if (candidate_server_kem->kem_extension_id == candidate_client_kem_id) {
                *chosen_kem = candidate_server_kem;
                return S2N_SUCCESS;
            }
        }
        GUARD(s2n_stuffer_reread(&client_kem_ids_stuffer));
    }

    /* Client and server did not propose any mutually supported KEMs compatible with the ciphersuite */
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_choose_kem_without_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_kem *server_kem_pref_list[],
        const uint8_t num_server_supported_kems, const struct s2n_kem **chosen_kem) {
    for (uint8_t i = 0; i < num_server_supported_kems; i++) {
        uint8_t kem_is_compatible = 0;
        GUARD(s2n_kem_check_kem_compatibility(iana_value, server_kem_pref_list[i], &kem_is_compatible));
        if (kem_is_compatible) {
            *chosen_kem = server_kem_pref_list[i];
            return S2N_SUCCESS;
        }
    }

    /* The server preference list did not contain any KEM extensions compatible with the ciphersuite */
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_kem_free(struct s2n_kem_params *kem_params)
{
    if (kem_params != NULL) {
        GUARD(s2n_blob_zeroize_free(&kem_params->private_key));
        GUARD(s2n_blob_zeroize_free(&kem_params->public_key));
        GUARD(s2n_blob_zeroize_free(&kem_params->shared_secret));
    }
    return S2N_SUCCESS;
}

int s2n_kem_group_free(struct s2n_kem_group_params *kem_group_params) {
    if (kem_group_params != NULL) {
        GUARD(s2n_kem_free(&kem_group_params->kem_params));
        GUARD(s2n_ecc_evp_params_free(&kem_group_params->ecc_params));
    }
    return S2N_SUCCESS;
}

int s2n_cipher_suite_to_kem(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_iana_to_kem **compatible_params)
{
    /* cppcheck-suppress knownConditionTrueFalse */
    ENSURE_POSIX(kem_mapping[0].kem_count > 0, S2N_ERR_KEM_UNSUPPORTED_PARAMS);

    for (int i = 0; i < s2n_array_len(kem_mapping); i++) {
        const struct s2n_iana_to_kem *candidate = &kem_mapping[i];
        if (memcmp(iana_value, candidate->iana_value, S2N_TLS_CIPHER_SUITE_LEN) == 0) {
            *compatible_params = candidate;
            return S2N_SUCCESS;
        }
    }
    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_get_kem_from_extension_id(kem_extension_size kem_id, const struct s2n_kem **kem) {
    /* cppcheck-suppress knownConditionTrueFalse */
    ENSURE_POSIX(kem_mapping[0].kem_count > 0, S2N_ERR_KEM_UNSUPPORTED_PARAMS);

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

    S2N_ERROR(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
}

int s2n_kem_send_public_key(struct s2n_stuffer *out, struct s2n_kem_params *kem_params) {
    notnull_check(out);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);

    const struct s2n_kem *kem = kem_params->kem;

    GUARD(s2n_stuffer_write_uint16(out, kem->public_key_length));

    /* We don't need to store the public key after sending it.
     * We write it directly to *out. */
    kem_params->public_key.data = s2n_stuffer_raw_write(out, kem->public_key_length);
    notnull_check(kem_params->public_key.data);
    kem_params->public_key.size = kem->public_key_length;

    /* Saves the private key in kem_params */
    GUARD(s2n_kem_generate_keypair(kem_params));

    /* After using s2n_stuffer_raw_write() above to write the public
     * key to the stuffer, we want to ensure that kem_params->public_key.data
     * does not continue to point at *out, else we may unexpectedly
     * overwrite part of the stuffer when s2n_kem_free() is called. */
    kem_params->public_key.data = NULL;
    kem_params->public_key.size = 0;

    return S2N_SUCCESS;
}

int s2n_kem_recv_public_key(struct s2n_stuffer *in, struct s2n_kem_params *kem_params) {
    notnull_check(in);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);

    const struct s2n_kem *kem = kem_params->kem;
    kem_public_key_size public_key_length;

    GUARD(s2n_stuffer_read_uint16(in, &public_key_length));
    S2N_ERROR_IF(public_key_length != kem->public_key_length, S2N_ERR_BAD_MESSAGE);

    /* Alloc memory for the public key; the peer receiving it will need it
     * later during the handshake to encapsulate the shared secret. */
    GUARD(s2n_alloc(&(kem_params->public_key), public_key_length));
    GUARD(s2n_stuffer_read_bytes(in, kem_params->public_key.data, public_key_length));

    return S2N_SUCCESS;
}

int s2n_kem_send_ciphertext(struct s2n_stuffer *out, struct s2n_kem_params *kem_params) {
    notnull_check(out);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);
    notnull_check(kem_params->public_key.data);

    const struct s2n_kem *kem = kem_params->kem;

    GUARD(s2n_stuffer_write_uint16(out, kem->ciphertext_length));

    /* Ciphertext will get written to *out */
    struct s2n_blob ciphertext = {.data = s2n_stuffer_raw_write(out, kem->ciphertext_length), .size = kem->ciphertext_length};
    notnull_check(ciphertext.data);

    /* Saves the shared secret in kem_params */
    GUARD(s2n_kem_encapsulate(kem_params, &ciphertext));

    return S2N_SUCCESS;
}

int s2n_kem_recv_ciphertext(struct s2n_stuffer *in, struct s2n_kem_params *kem_params) {
    notnull_check(in);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);
    notnull_check(kem_params->private_key.data);

    const struct s2n_kem *kem = kem_params->kem;
    kem_ciphertext_key_size ciphertext_length;

    GUARD(s2n_stuffer_read_uint16(in, &ciphertext_length));
    S2N_ERROR_IF(ciphertext_length != kem->ciphertext_length, S2N_ERR_BAD_MESSAGE);

    const struct s2n_blob ciphertext = {.data = s2n_stuffer_raw_read(in, ciphertext_length), .size = ciphertext_length};
    notnull_check(ciphertext.data);

    /* Saves the shared secret in kem_params */
    GUARD(s2n_kem_decapsulate(kem_params, &ciphertext));

    return S2N_SUCCESS;
}
