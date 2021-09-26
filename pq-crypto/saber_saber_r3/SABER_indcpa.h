#ifndef INDCPA_H
#define INDCPA_H

#include "SABER_params.h"

void indcpa_kem_keypair(uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[SABER_INDCPA_SECRETKEYBYTES]);
void indcpa_kem_enc(uint8_t m[SABER_KEYBYTES], uint8_t seed_sp[SABER_NOISE_SEEDBYTES], uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[SABER_BYTES_CCA_DEC]);
void indcpa_kem_dec(uint8_t sk[SABER_INDCPA_SECRETKEYBYTES], uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t m[SABER_KEYBYTES]);

#endif
