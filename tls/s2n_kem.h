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

#include <stdint.h>
#include "tls/s2n_crypto.h"
#include "utils/s2n_blob.h"

typedef uint16_t kem_extension_size;
typedef uint16_t kem_public_key_size;
typedef uint16_t kem_private_key_size;
typedef uint16_t kem_shared_secret_size;
typedef uint16_t kem_ciphertext_key_size;

struct s2n_kem {
    const char *name;
    const kem_extension_size kem_extension_id;
    const kem_public_key_size public_key_length;
    const kem_private_key_size private_key_length;
    const kem_shared_secret_size shared_secret_key_length;
    const kem_ciphertext_key_size ciphertext_length;
    /* NIST Post Quantum KEM submissions require the following API for compatibility */
    int (*generate_keypair)(unsigned char *public_key_out, unsigned char *private_key_out);
    int (*encapsulate)(unsigned char *ciphertext_out, unsigned char *shared_secret_out,  const unsigned char *public_key_in);
    int (*decapsulate)(unsigned char *shared_secret_out, const unsigned char *ciphertext_in, const unsigned char *private_key_in);
};

struct s2n_iana_to_kem {
    const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN];
    const struct s2n_kem **kems;
    uint8_t kem_count;
};

#if !defined(S2N_NO_PQ)

extern const struct s2n_kem s2n_bike1_l1_r1;
extern const struct s2n_kem s2n_bike1_l1_r2;
extern const struct s2n_kem s2n_sike_p503_r1;
extern const struct s2n_kem s2n_sike_p434_r2;

#endif

extern int s2n_kem_generate_keypair(struct s2n_kem_params *kem_params);
extern int s2n_kem_encapsulate(struct s2n_kem_params *kem_params, struct s2n_blob *ciphertext);
extern int s2n_kem_decapsulate(struct s2n_kem_params *kem_params, const struct s2n_blob *ciphertext);

extern int s2n_choose_kem_with_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], struct s2n_blob *client_kem_ids,
                                      const struct s2n_kem *server_kem_pref_list[], const uint8_t num_server_supported_kems,
                                      const struct s2n_kem **chosen_kem);

extern int s2n_choose_kem_without_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_kem *server_kem_pref_list[],
                                        const uint8_t num_server_supported_kems, const struct s2n_kem **chosen_kem);

extern int s2n_kem_free(struct s2n_kem_params *kem_params);

extern int s2n_cipher_suite_to_kem(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN], const struct s2n_iana_to_kem **supported_params);
extern int s2n_get_kem_from_extension_id(kem_extension_size kem_id, const struct s2n_kem **kem);
extern int s2n_kem_send_public_key(struct s2n_stuffer *out, struct s2n_kem_params *kem_params);
extern int s2n_kem_recv_public_key(struct s2n_stuffer *in, struct s2n_kem_params *kem_params);
extern int s2n_kem_send_ciphertext(struct s2n_stuffer *out, struct s2n_kem_params *kem_params);
extern int s2n_kem_recv_ciphertext(struct s2n_stuffer *in, struct s2n_kem_params *kem_params);
