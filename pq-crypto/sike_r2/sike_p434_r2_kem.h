#ifndef SIKE_P434_R2_KEM_H
#define SIKE_P434_R2_KEM_H

#include "../pq_utils.h"

#define SIKE_P434_r2_PUBLIC_KEY_BYTES 330
#define SIKE_P434_r2_SECRET_KEY_BYTES 374
#define SIKE_P434_r2_CIPHERTEXT_BYTES 346
#define SIKE_P434_r2_SHARED_SECRET_BYTES 16

// Keygenerate - pk is the public key
//               sk is the private key
// Return 0 for success and !0 for failures. See types.h for failure codes
int SIKE_P434_r2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
// Return 0 for success and !0 for failures.
int SIKE_P434_r2_crypto_kem_enc(OUT unsigned char *ct, OUT unsigned char *ss, IN const unsigned char *pk);

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
// Return 0 for success and !0 for failures.
int SIKE_P434_r2_crypto_kem_dec(OUT unsigned char *ss, IN const unsigned char *ct, IN const unsigned char *sk);

#endif // SIKE_P434_R2_KEM_H
