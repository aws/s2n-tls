// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_KYBER_H
#define OQS_KEM_KYBER_H

#include "pq_utils.h"

#define KYBER_512_R2_PUBLIC_KEY_BYTES 800
#define KYBER_512_R2_SECRET_KEY_BYTES 1632
#define KYBER_512_R2_CIPHERTEXT_BYTES 736
#define KYBER_512_R2_SHARED_SECRET_BYTES 32


//OQS_KEM *OQS_KEM_kyber_512_new(void);

// Keygenerate - pk is the public key
//               sk is the private key
// Return 0 for success and !0 for failures. See types.h for failure codes
int KYBER_512_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
// Return 0 for success and !0 for failures.
int KYBER_512_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
// Return 0 for success and !0 for failures.
int KYBER_512_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);


#endif

