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
#include "tls/s2n_crypto_constants.h"
#include "utils/s2n_blob.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_ecc_evp.h"

typedef uint16_t kem_extension_size;
typedef uint16_t kem_public_key_size;
typedef uint16_t kem_private_key_size;
typedef uint16_t kem_shared_secret_size;
typedef uint16_t kem_ciphertext_key_size;

#define IN /* Indicates a necessary function input */
#define OUT /* Indicates a function output */

struct s2n_kem {
    const char *name;
    const kem_extension_size kem_extension_id;
    const kem_public_key_size public_key_length;
    const kem_private_key_size private_key_length;
    const kem_shared_secret_size shared_secret_key_length;
    const kem_ciphertext_key_size ciphertext_length;
    /* NIST Post Quantum KEM submissions require the following API for compatibility */
    int (*generate_keypair)(OUT unsigned char *public_key, OUT unsigned char *private_key);
    int (*encapsulate)(OUT unsigned char *ciphertext, OUT unsigned char *shared_secret, IN const unsigned char *public_key);
    int (*decapsulate)(OUT unsigned char *shared_secret, IN const unsigned char *ciphertext, IN const unsigned char *private_key);
};

struct s2n_kem_params {
    const struct s2n_kem *kem;
    struct s2n_blob public_key;
    struct s2n_blob private_key;
    struct s2n_blob shared_secret;
};

struct s2n_iana_to_kem {
    const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN];
    const struct s2n_kem **kems;
    uint8_t kem_count;
};

struct s2n_kem_group {
    const char *name;
    uint16_t iana_id;
    uint16_t client_share_size;
    uint16_t server_share_size;
    const struct s2n_ecc_named_curve *curve;
    const struct s2n_kem *kem;
};

struct s2n_kem_group_params {
    const struct s2n_kem_group *kem_group;
    struct s2n_kem_params kem_params;
    struct s2n_ecc_evp_params ecc_params;
};

extern const struct s2n_kem s2n_bike1_l1_r1;
extern const struct s2n_kem s2n_bike1_l1_r2;
extern const struct s2n_kem s2n_bike_l1_r3;
extern const struct s2n_kem s2n_sike_p503_r1;
extern const struct s2n_kem s2n_sike_p434_r2;
extern const struct s2n_kem s2n_kyber_512_r2;
extern const struct s2n_kem s2n_kyber_512_90s_r2;
extern const struct s2n_kem s2n_kyber_512_r3;
extern const struct s2n_kem s2n_sike_p434_r3;

/* x25519 based tls13_kem_groups require EVP_APIS_SUPPORTED */
#if EVP_APIS_SUPPORTED
#define S2N_SUPPORTED_KEM_GROUPS_COUNT 6
#else
#define S2N_SUPPORTED_KEM_GROUPS_COUNT 3
#endif

extern const struct s2n_kem_group s2n_secp256r1_sike_p434_r2;
extern const struct s2n_kem_group s2n_secp256r1_bike1_l1_r2;
extern const struct s2n_kem_group s2n_secp256r1_kyber_512_r2;
extern const struct s2n_kem_group s2n_x25519_sike_p434_r2;
extern const struct s2n_kem_group s2n_x25519_bike1_l1_r2;
extern const struct s2n_kem_group s2n_x25519_kyber_512_r2;

extern S2N_RESULT s2n_kem_generate_keypair(struct s2n_kem_params *kem_params);
extern S2N_RESULT s2n_kem_encapsulate(struct s2n_kem_params *kem_params, struct s2n_blob *ciphertext);
extern S2N_RESULT s2n_kem_decapsulate(struct s2n_kem_params *kem_params, const struct s2n_blob *ciphertext);
extern int s2n_choose_kem_with_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN],
        struct s2n_blob *client_kem_ids, const struct s2n_kem *server_kem_pref_list[],
        const uint8_t num_server_supported_kems, const struct s2n_kem **chosen_kem);
extern int s2n_choose_kem_without_peer_pref_list(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN],
        const struct s2n_kem *server_kem_pref_list[], const uint8_t num_server_supported_kems,
        const struct s2n_kem **chosen_kem);
extern int s2n_kem_free(struct s2n_kem_params *kem_params);
extern int s2n_kem_group_free(struct s2n_kem_group_params *kem_group_params);
extern int s2n_cipher_suite_to_kem(const uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN],
        const struct s2n_iana_to_kem **supported_params);
extern int s2n_get_kem_from_extension_id(kem_extension_size kem_id, const struct s2n_kem **kem);
extern int s2n_kem_send_public_key(struct s2n_stuffer *out, struct s2n_kem_params *kem_params);
extern int s2n_kem_recv_public_key(struct s2n_stuffer *in, struct s2n_kem_params *kem_params);
extern int s2n_kem_send_ciphertext(struct s2n_stuffer *out, struct s2n_kem_params *kem_params);
extern int s2n_kem_recv_ciphertext(struct s2n_stuffer *in, struct s2n_kem_params *kem_params);

/* The following are API signatures for PQ KEMs as defined by NIST. All functions return 0
 * on success, and !0 on failure. Avoid calling these functions directly within s2n. Instead,
 * use s2n_kem_{generate_keypair, encapsulate, decapsulate}, or
 * s2n_kem_{send_public_key, recv_public_key, send_ciphertext, recv_ciphertext}.
 *
 *   int *_keypair(OUT pk, OUT sk) - Generate public/private keypair
 *   pk - generated public key
 *   sk - generated secret key
 *
 *   int *_enc(OUT ct, OUT ss, IN pk) - Generate a shared secret and encapsulate it
 *   ct - key encapsulation message (ciphertext)
 *   ss - plaintext shared secret
 *   pk - public key to use for encapsulation
 *
 *   int *_dec(OUT ss, IN ct, IN sk) - Decapsulate a key encapsulation message and recover the shared secret
 *   ss - plaintext shared secret
 *   ct - key encapsulation message (ciphertext)
 *   sk - secret key to use for decapsulation */

/* If s2n is compiled with support for PQ crypto, these functions will be defined in the respective KEM directories.
 * If s2n is compiled without support for PQ, stubs of these functions are defined in s2n_kem.c. */
/* sikep503r1 */
#define SIKE_P503_R1_SECRET_KEY_BYTES  434
#define SIKE_P503_R1_PUBLIC_KEY_BYTES  378
#define SIKE_P503_R1_CIPHERTEXT_BYTES 402
#define SIKE_P503_R1_SHARED_SECRET_BYTES 16
int SIKE_P503_r1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int SIKE_P503_r1_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN  const unsigned char *pk);
int SIKE_P503_r1_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* sikep434r2 */
#define SIKE_P434_R2_PUBLIC_KEY_BYTES 330
#define SIKE_P434_R2_SECRET_KEY_BYTES 374
#define SIKE_P434_R2_CIPHERTEXT_BYTES 346
#define SIKE_P434_R2_SHARED_SECRET_BYTES 16
int SIKE_P434_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int SIKE_P434_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int SIKE_P434_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* bike1_l1_r1 */
#define BIKE1_L1_R1_SECRET_KEY_BYTES    3110
#define BIKE1_L1_R1_PUBLIC_KEY_BYTES    2542
#define BIKE1_L1_R1_CIPHERTEXT_BYTES    2542
#define BIKE1_L1_R1_SHARED_SECRET_BYTES 32
int BIKE1_L1_R1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int BIKE1_L1_R1_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int BIKE1_L1_R1_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* bike1_l1_r2 */
#define BIKE1_L1_R2_SECRET_KEY_BYTES    6460
#define BIKE1_L1_R2_PUBLIC_KEY_BYTES    2946
#define BIKE1_L1_R2_CIPHERTEXT_BYTES    2946
#define BIKE1_L1_R2_SHARED_SECRET_BYTES 32
int BIKE1_L1_R2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int BIKE1_L1_R2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int BIKE1_L1_R2_crypto_kem_dec(OUT unsigned char * ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* bike_l1_r3 */
#define BIKE_L1_R3_SECRET_KEY_BYTES    5223
#define BIKE_L1_R3_PUBLIC_KEY_BYTES    1541
#define BIKE_L1_R3_CIPHERTEXT_BYTES    1573
#define BIKE_L1_R3_SHARED_SECRET_BYTES 32
int BIKE_L1_R3_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int BIKE_L1_R3_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int BIKE_L1_R3_crypto_kem_dec(OUT unsigned char * ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* kyber512r2 (the defined constants are identical for both regular and 90's version) */
#define KYBER_512_R2_PUBLIC_KEY_BYTES 800
#define KYBER_512_R2_SECRET_KEY_BYTES 1632
#define KYBER_512_R2_CIPHERTEXT_BYTES 736
#define KYBER_512_R2_SHARED_SECRET_BYTES 32
int kyber_512_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int kyber_512_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int kyber_512_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
int kyber_512_90s_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int kyber_512_90s_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int kyber_512_90s_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* kyber512r3 */
#define S2N_KYBER_512_R3_PUBLIC_KEY_BYTES 800
#define S2N_KYBER_512_R3_SECRET_KEY_BYTES 1632
#define S2N_KYBER_512_R3_CIPHERTEXT_BYTES 768
#define S2N_KYBER_512_R3_SHARED_SECRET_BYTES 32
int s2n_kyber_512_r3_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int s2n_kyber_512_r3_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int s2n_kyber_512_r3_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

/* sikep434r3 */
#define S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES 330
#define S2N_SIKE_P434_R3_SECRET_KEY_BYTES 374
#define S2N_SIKE_P434_R3_CIPHERTEXT_BYTES 346
#define S2N_SIKE_P434_R3_SHARED_SECRET_BYTES 16
int s2n_sike_p434_r3_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int s2n_sike_p434_r3_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int s2n_sike_p434_r3_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
