/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: API header file for P434
*********************************************************************************************/

#ifndef P434_API_H
#define P434_API_H

#include "P434_internal.h"

/*********************** Key encapsulation mechanism API ***********************/

#define CRYPTO_SECRETKEYBYTES 374 // MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes
#define CRYPTO_PUBLICKEYBYTES 330
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 346 // CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes

// Encoding of keys for KEM-based isogeny system "SIKEp434" (wire format):
// ----------------------------------------------------------------------
// Elements over GF(p434) are encoded in 55 octets in little endian format (i.e., the least significant octet is located in the lowest memory address).
// Elements (a+b*i) over GF(p434^2), where a and b are defined over GF(p434), are encoded as {a, b}, with a in the lowest memory portion.
//
// Private keys sk consist of the concatenation of a 16-byte random value, a value in the range [0, 2^217-1] and the public key pk. In the SIKE API,
// private keys are encoded in 374 octets in little endian format.
// Public keys pk consist of 3 elements in GF(p434^2). In the SIKE API, pk is encoded in 330 octets.
// Ciphertexts ct consist of the concatenation of a public key value and a 16-byte value. In the SIKE API, ct is encoded in 330 + 16 = 346 octets.
// Shared keys ss consist of a value of 16 octets.

/*********************** Ephemeral key exchange API ***********************/

// SECURITY NOTE: SIDH supports ephemeral Diffie-Hellman key exchange. It is NOT secure to use it with static keys.
// See "On the Security of Supersingular Isogeny Cryptosystems", S.D. Galbraith, C. Petit, B. Shani and Y.B. Ti, in ASIACRYPT 2016, 2016.
// Extended version available at: http://eprint.iacr.org/2016/859

// Generation of Alice's secret key
// Outputs random value in [0, 2^216 - 1] to be used as Alice's private key
void oqs_kem_sidh_p434_random_mod_order_A(unsigned char *random_digits);

// Generation of Bob's secret key
// Outputs random value in [0, 2^Floor(Log(2,3^137)) - 1] to be used as Bob's private key
void oqs_kem_sidh_p434_random_mod_order_B(unsigned char *random_digits);

// Alice's ephemeral public key generation
// Input:  a private key PrivateKeyA in the range [0, 2^216 - 1], stored in 27 bytes.
// Output: the public key PublicKeyA consisting of 3 GF(p434^2) elements encoded in 330 bytes.
int oqs_kem_sidh_p434_EphemeralKeyGeneration_A(const digit_t *PrivateKeyA, unsigned char *PublicKeyA);

// Bob's ephemeral key-pair generation
// It produces a private key PrivateKeyB and computes the public key PublicKeyB.
// The private key is an integer in the range [0, 2^Floor(Log(2,3^137)) - 1], stored in 28 bytes.
// The public key consists of 3 GF(p434^2) elements encoded in 330 bytes.
int oqs_kem_sidh_p434_EphemeralKeyGeneration_B(const digit_t *PrivateKeyB, unsigned char *PublicKeyB);

// Alice's ephemeral shared secret computation
// It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
// Inputs: Alice's PrivateKeyA is an integer in the range [0, 2^216 - 1], stored in 27 bytes.
//         Bob's PublicKeyB consists of 3 GF(p434^2) elements encoded in 330 bytes.
// Output: a shared secret SharedSecretA that consists of one element in GF(p434^2) encoded in 110 bytes.
int oqs_kem_sidh_p434_EphemeralSecretAgreement_A(const digit_t *PrivateKeyA, const unsigned char *PublicKeyB, unsigned char *SharedSecretA);

// Bob's ephemeral shared secret computation
// It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
// Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,3^137)) - 1], stored in 28 bytes.
//         Alice's PublicKeyA consists of 3 GF(p434^2) elements encoded in 330 bytes.
// Output: a shared secret SharedSecretB that consists of one element in GF(p434^2) encoded in 110 bytes.
int oqs_kem_sidh_p434_EphemeralSecretAgreement_B(const digit_t *PrivateKeyB, const unsigned char *PublicKeyA, unsigned char *SharedSecretB);


#endif
