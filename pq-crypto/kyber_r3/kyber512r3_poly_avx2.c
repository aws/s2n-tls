#include <stdint.h>
#include <immintrin.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly_avx2.h"
#include "kyber512r3_cbd_avx2.h"
#include "kyber512r3_consts_avx2.h"
#include "kyber512r3_reduce_avx2.h"
#include "kyber512r3_ntt_avx2.h"
#include "kyber512r3_symmetric.h"
#include "kyber512r3_fips202x4_avx2.h"
#include <immintrin.h>

/*************************************************
* Name:        poly_compress_avx2
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES)
*              - poly *a:    pointer to input polynomial
**************************************************/

// S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES == 128
void poly_compress_avx2(uint8_t r[128], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i v = _mm256_load_si256((const void *)&qdata[_16XV]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 9);
  const __m256i mask = _mm256_set1_epi16(15);
  const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
  const __m256i permdidx = _mm256_set_epi32(7,3,6,2,5,1,4,0);

  for(i=0;i<S2N_KYBER_512_R3_N/64;i++) {
    f0 = _mm256_load_si256((const void *)&a->coeffs[64*i+ 0]);
    f1 = _mm256_load_si256((const void *)&a->coeffs[64*i+16]);
    f2 = _mm256_load_si256((const void *)&a->coeffs[64*i+32]);
    f3 = _mm256_load_si256((const void *)&a->coeffs[64*i+48]);
    f0 = _mm256_mulhi_epi16(f0,v);
    f1 = _mm256_mulhi_epi16(f1,v);
    f2 = _mm256_mulhi_epi16(f2,v);
    f3 = _mm256_mulhi_epi16(f3,v);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f2 = _mm256_mulhrs_epi16(f2,shift1);
    f3 = _mm256_mulhrs_epi16(f3,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f1 = _mm256_and_si256(f1,mask);
    f2 = _mm256_and_si256(f2,mask);
    f3 = _mm256_and_si256(f3,mask);
    f0 = _mm256_packus_epi16(f0,f1);
    f2 = _mm256_packus_epi16(f2,f3);
    f0 = _mm256_maddubs_epi16(f0,shift2);
    f2 = _mm256_maddubs_epi16(f2,shift2);
    f0 = _mm256_packus_epi16(f0,f2);
    f0 = _mm256_permutevar8x32_epi32(f0,permdidx);
    _mm256_storeu_si256((void *)&r[32*i],f0);
  }
}

void poly_decompress_avx2(poly * restrict r, const uint8_t a[128])
{
  unsigned int i;
  __m256i f;
  const __m256i q = _mm256_load_si256((const void *)&qdata[_16XQ]);
  const __m256i shufbidx = _mm256_set_epi8(7,7,7,7,6,6,6,6,5,5,5,5,4,4,4,4,
                                           3,3,3,3,2,2,2,2,1,1,1,1,0,0,0,0);
  const __m256i mask = _mm256_set1_epi32(0x00F0000F);
  const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);

  for(i=0;i<S2N_KYBER_512_R3_N/16;i++) {
    f = _mm256_broadcastq_epi64(_mm_loadl_epi64((const void *)&a[8*i]));
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256((void *)&r->coeffs[16*i],f);
  }
}

/*************************************************
* Name:        poly_tobytes_avx2
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for S2N_KYBER_512_R3_POLYBYTES bytes)
*              - poly *a:    pointer to input polynomial
**************************************************/
void poly_tobytes_avx2(uint8_t r[S2N_KYBER_512_R3_POLYBYTES], poly *a)
{
  ntttobytes_avx2_asm(r, a->coeffs, qdata);
}

/*************************************************
* Name:        poly_frombytes_avx2
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes_avx2
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of S2N_KYBER_512_R3_POLYBYTES bytes)
**************************************************/
void poly_frombytes_avx2(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYBYTES])
{
  nttfrombytes_avx2_asm(r->coeffs, a, qdata);
}

/*************************************************
* Name:        poly_frommsg_avx2
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_frommsg_avx2(poly * restrict r,
                  const uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES])
{
  __m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
  const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0,1,2,3));
  const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(15,14,11,10,7,6,3,2,13,12,9,8,5,4,1,0));
  const __m256i hqs = _mm256_set1_epi16((S2N_KYBER_512_R3_Q+1)/2);

#define FROMMSG64(i)						\
  g3 = _mm256_shuffle_epi32(f,0x55*i);				\
  g3 = _mm256_sllv_epi32(g3,shift);				\
  g3 = _mm256_shuffle_epi8(g3,idx);				\
  g0 = _mm256_slli_epi16(g3,12);				\
  g1 = _mm256_slli_epi16(g3,8);					\
  g2 = _mm256_slli_epi16(g3,4);					\
  g0 = _mm256_srai_epi16(g0,15);				\
  g1 = _mm256_srai_epi16(g1,15);				\
  g2 = _mm256_srai_epi16(g2,15);				\
  g3 = _mm256_srai_epi16(g3,15);				\
  g0 = _mm256_and_si256(g0,hqs);  /* 19 18 17 16  3  2  1  0 */	\
  g1 = _mm256_and_si256(g1,hqs);  /* 23 22 21 20  7  6  5  4 */	\
  g2 = _mm256_and_si256(g2,hqs);  /* 27 26 25 24 11 10  9  8 */	\
  g3 = _mm256_and_si256(g3,hqs);  /* 31 30 29 28 15 14 13 12 */	\
  h0 = _mm256_unpacklo_epi64(g0,g1);				\
  h2 = _mm256_unpackhi_epi64(g0,g1);				\
  h1 = _mm256_unpacklo_epi64(g2,g3);				\
  h3 = _mm256_unpackhi_epi64(g2,g3);				\
  g0 = _mm256_permute2x128_si256(h0,h1,0x20);			\
  g2 = _mm256_permute2x128_si256(h0,h1,0x31);			\
  g1 = _mm256_permute2x128_si256(h2,h3,0x20);			\
  g3 = _mm256_permute2x128_si256(h2,h3,0x31);			\
  _mm256_store_si256((void *)&r->coeffs[  0+32*i+ 0],g0);	\
  _mm256_store_si256((void *)&r->coeffs[  0+32*i+16],g1);	\
  _mm256_store_si256((void *)&r->coeffs[128+32*i+ 0],g2);	\
  _mm256_store_si256((void *)&r->coeffs[128+32*i+16],g3)

  f = _mm256_load_si256((const void *)msg);
  FROMMSG64(0);
  FROMMSG64(1);
  FROMMSG64(2);
  FROMMSG64(3);
}

/*************************************************
* Name:        poly_tomsg_avx2
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - poly *a:      pointer to input polynomial
**************************************************/
void poly_tomsg_avx2(uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES], poly * restrict a)
{
  unsigned int i;
  uint32_t small;
  __m256i f0, f1, g0, g1;
  const __m256i hqs = _mm256_set1_epi16((S2N_KYBER_512_R3_Q - 1)/2);
  const __m256i hhqs = _mm256_set1_epi16((S2N_KYBER_512_R3_Q - 5)/4);

  for(i=0;i<S2N_KYBER_512_R3_N/32;i++) {
    f0 = _mm256_load_si256((void *)&a->coeffs[32*i]);
    f1 = _mm256_load_si256((void *)&a->coeffs[32*i+16]);
    f0 = _mm256_sub_epi16(hqs, f0);
    f1 = _mm256_sub_epi16(hqs, f1);
    g0 = _mm256_srai_epi16(f0, 15);
    g1 = _mm256_srai_epi16(f1, 15);
    f0 = _mm256_xor_si256(f0, g0);
    f1 = _mm256_xor_si256(f1, g1);
    f0 = _mm256_sub_epi16(hhqs, f0);
    f1 = _mm256_sub_epi16(hhqs, f1);
    f0 = _mm256_packs_epi16(f0, f1);
    small = _mm256_movemask_epi8(f0);
    small = ~small;
    msg[4*i+0] = small;
    msg[4*i+1] = small >> 16;
    msg[4*i+2] = small >>  8;
    msg[4*i+3] = small >> 24;
  }
}

/*************************************************
* Name:        poly_getnoise_eta2_avx2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter S2N_KYBER_512_R3_ETA2
*
* Arguments:   - poly *r:             pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length S2N_KYBER_512_R3_SYMBYTES bytes)
*              - uint8_t nonce:       one-byte input nonce
**************************************************/
void poly_getnoise_eta2_avx2(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce)
{
  __attribute__((aligned(32)))
  uint8_t buf[S2N_KYBER_512_R3_ETA2*S2N_KYBER_512_R3_N/4];
  shake256_prf(buf, sizeof(buf), seed, nonce);
  cbd_eta2_avx2(r, buf);
}

void poly_getnoise_eta1_4x(poly *r0,
                     poly *r1,
                     poly *r2,
                     poly *r3,
                     const uint8_t seed[32],
                     uint8_t nonce0,
                     uint8_t nonce1,
                     uint8_t nonce2,
                     uint8_t nonce3)
{
  __attribute__((aligned(32)))
  uint8_t buf[4][288]; /* 288 instead of 2*S2N_KYBER_512_R3_SHAKE256_RATE for better alignment, also 2 extra bytes needed in cbd3 */
  __m256i f;
  keccakx4_state state;

  f = _mm256_load_si256((const void *)seed);
  _mm256_store_si256((void *)buf[0], f);
  _mm256_store_si256((void *)buf[1], f);
  _mm256_store_si256((void *)buf[2], f);
  _mm256_store_si256((void *)buf[3], f);

  buf[0][32] = nonce0;
  buf[1][32] = nonce1;
  buf[2][32] = nonce2;
  buf[3][32] = nonce3;

  shake256x4_absorb(&state, buf[0], buf[1], buf[2], buf[3], 33);
  shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 2, &state);

  cbd_eta1_avx2(r0, buf[0]);
  cbd_eta1_avx2(r1, buf[1]);
  cbd_eta1_avx2(r2, buf[2]);
  cbd_eta1_avx2(r3, buf[3]);
}

void poly_getnoise_eta1122_4x(poly *r0,
                     poly *r1,
                     poly *r2,
                     poly *r3,
                     const uint8_t seed[32],
                     uint8_t nonce0,
                     uint8_t nonce1,
                     uint8_t nonce2,
                     uint8_t nonce3)
{
  __attribute__((aligned(32)))
  uint8_t buf[4][288]; /* 288 instead of 2*S2N_KYBER_512_R3_SHAKE256_RATE for better alignment, also 2 extra bytes needed in cbd3 */
  __m256i f;
  keccakx4_state state;

  f = _mm256_load_si256((const void *)seed);
  _mm256_store_si256((void *)buf[0], f);
  _mm256_store_si256((void *)buf[1], f);
  _mm256_store_si256((void *)buf[2], f);
  _mm256_store_si256((void *)buf[3], f);

  buf[0][32] = nonce0;
  buf[1][32] = nonce1;
  buf[2][32] = nonce2;
  buf[3][32] = nonce3;

  shake256x4_absorb(&state, buf[0], buf[1], buf[2], buf[3], 33);
  shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 2, &state);

  cbd_eta1_avx2(r0, buf[0]);
  cbd_eta1_avx2(r1, buf[1]);
  cbd_eta2_avx2(r2, buf[2]);
  cbd_eta2_avx2(r3, buf[3]);
}

/*************************************************
* Name:        poly_ntt_avx2
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void poly_ntt_avx2(poly *r)
{
  ntt_avx2_asm(r->coeffs, qdata);
}

/*************************************************
* Name:        poly_invntt_tomont_avx2
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void poly_invntt_tomont_avx2(poly *r)
{
  invntt_avx2_asm(r->coeffs, qdata);
}

void poly_nttunpack_avx2(poly *r)
{
  nttunpack_avx2_asm(r->coeffs, qdata);
}

/*************************************************
* Name:        poly_basemul_montgomery_avx2
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery_avx2(poly *r, const poly *a, const poly *b)
{
  basemul_avx2_asm(r->coeffs, a->coeffs, b->coeffs, qdata);
}

/*************************************************
* Name:        poly_tomont_avx2
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_tomont_avx2(poly *r)
{
  tomont_avx2_asm(r->coeffs, qdata);
}

/*************************************************
* Name:        poly_reduce_avx2
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_reduce_avx2(poly *r)
{
  reduce_avx2_asm(r->coeffs, qdata);
}

/*************************************************
* Name:        poly_add_avx2
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_add_avx2(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for(i=0;i<S2N_KYBER_512_R3_N;i+=16) {
    f0 = _mm256_load_si256((const void *)&a->coeffs[i]);
    f1 = _mm256_load_si256((const void *)&b->coeffs[i]);
    f0 = _mm256_add_epi16(f0, f1);
    _mm256_store_si256((void *)&r->coeffs[i], f0);
  }
}

/*************************************************
* Name:        poly_sub_avx2
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_sub_avx2(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for(i=0;i<S2N_KYBER_512_R3_N;i+=16) {
    f0 = _mm256_load_si256((const void *)&a->coeffs[i]);
    f1 = _mm256_load_si256((const void *)&b->coeffs[i]);
    f0 = _mm256_sub_epi16(f0, f1);
    _mm256_store_si256((void *)&r->coeffs[i], f0);
  }
}
