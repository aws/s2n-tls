#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"

#define indcpa_keypair S2N_KYBER_512_R3_NAMESPACE(indcpa_keypair)
int indcpa_keypair(uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES], uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc S2N_KYBER_512_R3_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES], const uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES],
        const uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES], const uint8_t coins[S2N_KYBER_512_R3_SYMBYTES]);

#define indcpa_dec S2N_KYBER_512_R3_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES], const uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES],
        const uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]);
