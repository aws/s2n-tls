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


#ifdef S2N_KYBER512R3_AVX2_BMI2

//#define gen_matrix_avx2 S2N_KYBER_512_R3_NAMESPACE(gen_matrix_avx2)
//void gen_matrix_avx2(polyvec *a, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], int transposed);

#define indcpa_keypair_avx2 S2N_KYBER_512_R3_NAMESPACE(indcpa_keypair_avx2)
int indcpa_keypair_avx2(uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc_avx2 S2N_KYBER_512_R3_NAMESPACE(indcpa_enc_avx2)
void indcpa_enc_avx2(uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES],
                const uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES],
                const uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[S2N_KYBER_512_R3_SYMBYTES]);

#define indcpa_dec_avx2 S2N_KYBER_512_R3_NAMESPACE(indcpa_dec_avx2)
void indcpa_dec_avx2(uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES],
                const uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES],
                const uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]);

#endif
