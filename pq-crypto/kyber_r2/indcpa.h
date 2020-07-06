#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>

int PQCLEAN_KYBER512_CLEAN_indcpa_keypair(
    uint8_t *pk,
    uint8_t *sk);

void PQCLEAN_KYBER512_CLEAN_indcpa_enc(
    uint8_t *c,
    const uint8_t *m,
    const uint8_t *pk,
    const uint8_t *coins);

void PQCLEAN_KYBER512_CLEAN_indcpa_dec(
    uint8_t *m,
    const uint8_t *c,
    const uint8_t *sk);

#endif
