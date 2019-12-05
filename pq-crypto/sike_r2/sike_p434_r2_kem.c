/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/

#include <string.h>
#include "../pq_random.h"
#include "fips202.h"

int SIKE_P434_r2_crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    // SIKE's key generation
    // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          public key pk (CRYPTO_PUBLICKEYBYTES bytes)

    digit_t _sk[(SECRETKEY_B_BYTES / sizeof(digit_t)) + 1];

    // Generate lower portion of secret key sk <- s||SK
    get_random_bytes(sk, MSG_BYTES);
    random_mod_order_B((unsigned char *)_sk);

    // Generate public key pk
    EphemeralKeyGeneration_B(_sk, pk);

    memcpy(sk + MSG_BYTES, _sk, SECRETKEY_B_BYTES);

    // Append public key pk to secret key sk
    memcpy(&sk[MSG_BYTES + SECRETKEY_B_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

    return 0;
}

int SIKE_P434_r2_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    // SIKE's encapsulation
    // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)

    union {
        unsigned char b[SECRETKEY_A_BYTES];
        digit_t       d[SECRETKEY_A_BYTES/sizeof(digit_t)];
    } ephemeralsk;
    unsigned char jinvariant[FP2_ENCODED_BYTES];
    unsigned char h[MSG_BYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES + MSG_BYTES];

    // Generate ephemeralsk <- G(m||pk) mod oA
    get_random_bytes(temp, MSG_BYTES);
    memcpy(&temp[MSG_BYTES], pk, CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk.b, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES + MSG_BYTES);
    ephemeralsk.b[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Encrypt
    EphemeralKeyGeneration_A(ephemeralsk.d, ct);
    EphemeralSecretAgreement_A(ephemeralsk.d, pk, jinvariant);
    shake256(h, MSG_BYTES, jinvariant, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        ct[i + CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];
    }
    // Generate shared secret ss <- H(m||ct)
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);

    return 0;
}

int SIKE_P434_r2_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    // SIKE's decapsulation
    // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)

    union {
        unsigned char b[SECRETKEY_A_BYTES];
        digit_t       d[SECRETKEY_A_BYTES/sizeof(digit_t)];
    } ephemeralsk_;
    unsigned char jinvariant_[FP2_ENCODED_BYTES];
    unsigned char h_[MSG_BYTES];
    unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES + MSG_BYTES];

    digit_t _sk[(SECRETKEY_B_BYTES / sizeof(digit_t)) + 1];
    memcpy(_sk, sk + MSG_BYTES, SECRETKEY_B_BYTES);

    // Decrypt
    EphemeralSecretAgreement_B(_sk, ct, jinvariant_);
    shake256(h_, MSG_BYTES, jinvariant_, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        temp[i] = ct[i + CRYPTO_PUBLICKEYBYTES] ^ h_[i];
    }
    // Generate ephemeralsk_ <- G(m||pk) mod oA
    memcpy(&temp[MSG_BYTES], &sk[MSG_BYTES + SECRETKEY_B_BYTES], CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk_.b, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES + MSG_BYTES);
    ephemeralsk_.b[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Generate shared secret ss <- H(m||ct) or output ss <- H(s||ct)
    EphemeralKeyGeneration_A(ephemeralsk_.d, c0_);
    if (memcmp(c0_, ct, CRYPTO_PUBLICKEYBYTES) != 0) {
        memcpy(temp, sk, MSG_BYTES);
    }
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);

    return 0;
}
