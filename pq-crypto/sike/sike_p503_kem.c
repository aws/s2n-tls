/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/ 

#include "sike_p503_kem.h"

#include <string.h>
#include "P503_internal.h"
#include "fips202.h"
#include "pq-crypto/pq-random.h"

int SIKE_P503_crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{ // SIKE's key generation
  // Outputs: secret key sk (SIKE_P503_SECRET_KEY_BYTES = MSG_BYTES + SECRETKEY_B_BYTES + SIKE_P503_PUBLIC_KEY_BYTES bytes)
  //          public key pk (SIKE_P503_PUBLIC_KEY_BYTES bytes) 

    // Generate lower portion of secret key sk <- s||SK
    get_random_bytes(sk, MSG_BYTES);
    random_mod_order_B(sk + MSG_BYTES);

    // Generate public key pk
    EphemeralKeyGeneration_B(sk + MSG_BYTES, pk);

    // Append public key pk to secret key sk
    memcpy(&sk[MSG_BYTES + SECRETKEY_B_BYTES], pk, SIKE_P503_PUBLIC_KEY_BYTES);

    return 0;
}


int SIKE_P503_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // SIKE's encapsulation
  // Input:   public key pk         (SIKE_P503_PUBLIC_KEY_BYTES bytes)
  // Outputs: shared secret ss      (SIKE_P503_SHARED_SECRET_BYTES bytes)
  //          ciphertext message ct (SIKE_P503_CIPHERTEXT_BYTES = SIKE_P503_PUBLIC_KEY_BYTES + MSG_BYTES bytes) 
    const uint16_t G = 0;
    const uint16_t H = 1;
    const uint16_t P = 2;
    unsigned char ephemeralsk[SECRETKEY_A_BYTES];
    unsigned char jinvariant[FP2_ENCODED_BYTES];
    unsigned char h[MSG_BYTES];
    unsigned char temp[SIKE_P503_CIPHERTEXT_BYTES+MSG_BYTES];
    unsigned int i;

    // Generate ephemeralsk <- G(m||pk) mod oA 
    get_random_bytes(temp, MSG_BYTES);
    memcpy(&temp[MSG_BYTES], pk, SIKE_P503_PUBLIC_KEY_BYTES);
    cshake256_simple(ephemeralsk, SECRETKEY_A_BYTES, G, temp, SIKE_P503_PUBLIC_KEY_BYTES+MSG_BYTES);
    ephemeralsk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Encrypt
    EphemeralKeyGeneration_A(ephemeralsk, ct);
    EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);
    cshake256_simple(h, MSG_BYTES, P, jinvariant, FP2_ENCODED_BYTES);
    for (i = 0; i < MSG_BYTES; i++) ct[i + SIKE_P503_PUBLIC_KEY_BYTES] = temp[i] ^ h[i];

    // Generate shared secret ss <- H(m||ct)
    memcpy(&temp[MSG_BYTES], ct, SIKE_P503_CIPHERTEXT_BYTES);
    cshake256_simple(ss, SIKE_P503_SHARED_SECRET_BYTES, H, temp, SIKE_P503_CIPHERTEXT_BYTES+MSG_BYTES);

    return 0;
}


int SIKE_P503_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // SIKE's decapsulation
  // Input:   secret key sk         (SIKE_P503_SECRET_KEY_BYTES = MSG_BYTES + SECRETKEY_B_BYTES + SIKE_P503_PUBLIC_KEY_BYTES bytes)
  //          ciphertext message ct (SIKE_P503_CIPHERTEXT_BYTES = SIKE_P503_PUBLIC_KEY_BYTES + MSG_BYTES bytes) 
  // Outputs: shared secret ss      (SIKE_P503_SHARED_SECRET_BYTES bytes)
    const uint16_t G = 0;
    const uint16_t H = 1;
    const uint16_t P = 2;
    unsigned char ephemeralsk_[SECRETKEY_A_BYTES];
    unsigned char jinvariant_[FP2_ENCODED_BYTES];
    unsigned char h_[MSG_BYTES];
    unsigned char c0_[SIKE_P503_PUBLIC_KEY_BYTES];
    unsigned char temp[SIKE_P503_CIPHERTEXT_BYTES+MSG_BYTES];
    unsigned int i;

    // Decrypt
    EphemeralSecretAgreement_B(sk + MSG_BYTES, ct, jinvariant_);
    cshake256_simple(h_, MSG_BYTES, P, jinvariant_, FP2_ENCODED_BYTES);
    for (i = 0; i < MSG_BYTES; i++) temp[i] = ct[i + SIKE_P503_PUBLIC_KEY_BYTES] ^ h_[i];

    // Generate ephemeralsk_ <- G(m||pk) mod oA
    memcpy(&temp[MSG_BYTES], &sk[MSG_BYTES + SECRETKEY_B_BYTES], SIKE_P503_PUBLIC_KEY_BYTES);
    cshake256_simple(ephemeralsk_, SECRETKEY_A_BYTES, G, temp, SIKE_P503_PUBLIC_KEY_BYTES+MSG_BYTES);
    ephemeralsk_[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;
    
    // Generate shared secret ss <- H(m||ct) or output ss <- H(s||ct)
    EphemeralKeyGeneration_A(ephemeralsk_, c0_);
    if (memcmp(c0_, ct, SIKE_P503_PUBLIC_KEY_BYTES) != 0) {
        memcpy(temp, sk, MSG_BYTES);
    }
    memcpy(&temp[MSG_BYTES], ct, SIKE_P503_CIPHERTEXT_BYTES);
    cshake256_simple(ss, SIKE_P503_SHARED_SECRET_BYTES, H, temp, SIKE_P503_CIPHERTEXT_BYTES+MSG_BYTES);

    return 0;
}
