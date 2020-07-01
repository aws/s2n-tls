#ifndef KYBER_R2_KEM_H
#define KYBER_R2_KEM_H

#include "../pq_utils.h"

#define KYBER_512_R2_PUBLIC_KEY_BYTES 800
#define KYBER_512_R2_SECRET_KEY_BYTES 1632
#define KYBER_512_R2_CIPHERTEXT_BYTES 736
#define KYBER_512_R2_SHARED_SECRET_BYTES 32

// Keygenerate - pk is the public key
//               sk is the private key
// Return 0 for success and !0 for failures. See types.h for failure codes
int kyber_512_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
// Return 0 for success and !0 for failures.
int kyber_512_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
// Return 0 for success and !0 for failures.
int kyber_512_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

#endif // KYBER_R2_KEM_H

