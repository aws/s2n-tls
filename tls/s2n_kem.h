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
    S2N_RESULT (*generate_keypair)(OUT uint8_t *public_key, OUT uint8_t *private_key);
    S2N_RESULT (*encapsulate)(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
    S2N_RESULT (*decapsulate)(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);
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
extern const struct s2n_kem s2n_sike_p503_r1;
extern const struct s2n_kem s2n_sike_p434_r2;
extern const struct s2n_kem s2n_kyber_512_r2;
extern const struct s2n_kem s2n_kyber_512_90s_r2;

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

extern int s2n_kem_generate_keypair(struct s2n_kem_params *kem_params);
extern int s2n_kem_encapsulate(struct s2n_kem_params *kem_params, struct s2n_blob *ciphertext);
extern int s2n_kem_decapsulate(struct s2n_kem_params *kem_params, const struct s2n_blob *ciphertext);
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

/* Wrappers for the NIST PQ KEM functions, intended for consumptions within s2n. */
/* sikep503r1 */
#define SIKE_P503_R1_SECRET_KEY_BYTES  434
#define SIKE_P503_R1_PUBLIC_KEY_BYTES  378
#define SIKE_P503_R1_CIPHERTEXT_BYTES 402
#define SIKE_P503_R1_SHARED_SECRET_BYTES 16
S2N_RESULT s2n_sikep503r1_keygen(OUT uint8_t *public_key, OUT uint8_t *private_key);
S2N_RESULT s2n_sikep503r1_enc(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN  const uint8_t *public_key);
S2N_RESULT s2n_sikep503r1_dec(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);

/* sikep434r2 */
#define SIKE_P434_R2_PUBLIC_KEY_BYTES 330
#define SIKE_P434_R2_SECRET_KEY_BYTES 374
#define SIKE_P434_R2_CIPHERTEXT_BYTES 346
#define SIKE_P434_R2_SHARED_SECRET_BYTES 16
S2N_RESULT s2n_sikep434r2_keygen(OUT uint8_t *public_key, OUT uint8_t *private_key);
S2N_RESULT s2n_sikep434r2_enc(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
S2N_RESULT s2n_sikep434r2_dec(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);

/* bike1l1r1 */
#define BIKE1_L1_R1_SECRET_KEY_BYTES    3110
#define BIKE1_L1_R1_PUBLIC_KEY_BYTES    2542
#define BIKE1_L1_R1_CIPHERTEXT_BYTES    2542
#define BIKE1_L1_R1_SHARED_SECRET_BYTES 32
S2N_RESULT s2n_bike1l1r1_keygen(OUT uint8_t *public_key, OUT uint8_t *private_key);
S2N_RESULT s2n_bike1l1r1_enc(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
S2N_RESULT s2n_bike1l1r1_dec(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);

/* bike1l1r2 */
#define BIKE1_L1_R2_SECRET_KEY_BYTES    6460
#define BIKE1_L1_R2_PUBLIC_KEY_BYTES    2946
#define BIKE1_L1_R2_CIPHERTEXT_BYTES    2946
#define BIKE1_L1_R2_SHARED_SECRET_BYTES 32
S2N_RESULT s2n_bike1l1r2_keygen(OUT uint8_t *public_key, OUT uint8_t *private_key);
S2N_RESULT s2n_bike1l1r2_enc(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
S2N_RESULT s2n_bike1l1r2_dec(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);

/* kyber512r2 */
#define KYBER_512_R2_PUBLIC_KEY_BYTES 800
#define KYBER_512_R2_SECRET_KEY_BYTES 1632
#define KYBER_512_R2_CIPHERTEXT_BYTES 736
#define KYBER_512_R2_SHARED_SECRET_BYTES 32
S2N_RESULT s2n_kyber512r2_keygen(OUT uint8_t *public_key, OUT uint8_t *private_key);
S2N_RESULT s2n_kyber512r2_enc(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
S2N_RESULT s2n_kyber512r2_dec(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);

/* kyber512r2 90's version*/
/* The lengths of public key, private key, ciphertext, and shared secret are the same as the regular kyber512r2. */
S2N_RESULT s2n_kyber51290sr2_keygen(OUT uint8_t *public_key, OUT uint8_t *private_key);
S2N_RESULT s2n_kyber51290sr2_enc(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
S2N_RESULT s2n_kyber51290sr2_dec(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);

/*
 * The following are API signatures for PQ KEMs as defined by NIST. All functions return 0 on success,
 * and !0 on failure. Avoid calling these functions directly. The wrappers defined above are intended
 * for general consumption within s2n
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
int SIKE_P503_r1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int SIKE_P503_r1_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN  const unsigned char *pk);
int SIKE_P503_r1_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
/* sikep434r2 */
int SIKE_P434_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int SIKE_P434_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int SIKE_P434_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
/* bike1l1r1 */
int BIKE1_L1_R1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int BIKE1_L1_R1_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int BIKE1_L1_R1_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
/* bike1l1r2*/
int BIKE1_L1_R2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int BIKE1_L1_R2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int BIKE1_L1_R2_crypto_kem_dec(OUT unsigned char * ss, IN const unsigned char *ct, IN const unsigned char *sk);
/* kyber512r2 */
int kyber_512_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int kyber_512_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int kyber_512_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
/* kyber512r2 90's version*/
int kyber_512_90s_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);
int kyber_512_90s_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);
int kyber_512_90s_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);
