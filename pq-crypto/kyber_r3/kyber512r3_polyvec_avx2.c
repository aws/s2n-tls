#include <stdint.h>
#include <string.h>
#include "kyber512r3_polyvec_avx2.h"
#include "kyber512r3_poly_avx2.h"
#include "kyber512r3_consts_avx2.h"

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#include <immintrin.h>

static void poly_compress10(uint8_t r[320], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i v8 = _mm256_slli_epi16(v,3);
  const __m256i off = _mm256_set1_epi16(15);
  const __m256i shift1 = _mm256_set1_epi16(1 << 12);
  const __m256i mask = _mm256_set1_epi16(1023);
  const __m256i shift2 = _mm256_set1_epi64x((1024LL << 48) + (1LL << 32) + (1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8( 8, 4, 3, 2, 1, 0,-1,-1,-1,-1,-1,-1,12,11,10, 9,
                                           -1,-1,-1,-1,-1,-1,12,11,10, 9, 8, 4, 3, 2, 1, 0);

  for(i=0;i<S2N_KYBER_512_R3_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_mullo_epi16(f0,v8);
    f2 = _mm256_add_epi16(f0,off);
    f0 = _mm256_slli_epi16(f0,3);
    f0 = _mm256_mulhi_epi16(f0,v);
    f2 = _mm256_sub_epi16(f1,f2);
    f1 = _mm256_andnot_si256(f1,f2);
    f1 = _mm256_srli_epi16(f1,15);
    f0 = _mm256_sub_epi16(f0,f1);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f0 = _mm256_madd_epi16(f0,shift2);
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f0 = _mm256_srli_epi64(f0,12);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blend_epi16(t0,t1,0xE0);
    // correcting cast-align error
    // old version: _mm_storeu_si128((__m128i *)&r[20*i+ 0],t0);
    _mm_storeu_si128((void *)&r[20*i+ 0],t0);
    memcpy(&r[20*i+16],&t1,4);
  }
}

static void poly_decompress10(poly * restrict r, const uint8_t a[320+12])
{
  unsigned int i;
  __m256i f;
  const __m256i q = _mm256_set1_epi32((S2N_KYBER_512_R3_Q << 16) + 4*S2N_KYBER_512_R3_Q);
  const __m256i shufbidx = _mm256_set_epi8(11,10,10, 9, 9, 8, 8, 7,
                                            6, 5, 5, 4, 4, 3, 3, 2,
                                            9, 8, 8, 7, 7, 6, 6, 5,
                                            4, 3, 3, 2, 2, 1, 1, 0);
  const __m256i sllvdidx = _mm256_set1_epi64x(4);
  const __m256i mask = _mm256_set1_epi32((32736 << 16) + 8184);

  for(i=0;i<S2N_KYBER_512_R3_N/16;i++) {
    // correcting cast-align and cast-qual errors
    // old version: f = _mm256_loadu_si256((__m256i *)&a[20*i]);
    f = _mm256_loadu_si256((const void *)&a[20*i]);
    f = _mm256_permute4x64_epi64(f,0x94);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_sllv_epi32(f,sllvdidx);
    f = _mm256_srli_epi16(f,1);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}

/*************************************************
* Name:        polyvec_compress_avx2
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES)
*                       - polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_compress_avx2(uint8_t r[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES+2], const polyvec *a)
{
  unsigned int i;

  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_compress10(&r[320*i],&a->vec[i]);
}

/*************************************************
* Name:        polyvec_decompress_avx2
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress_avx2
*
* Arguments:   - polyvec *r: pointer to output vector of polynomials
*                       - const uint8_t *a: pointer to input byte array
*                                  (of length S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES)
**************************************************/
void polyvec_decompress_avx2(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES+12])
{
  unsigned int i;

  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_decompress10(&r->vec[i],&a[320*i]);
}

/*************************************************
* Name:        polyvec_tobytes_avx2
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for S2N_KYBER_512_R3_POLYVECBYTES)
*                       - polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes_avx2(uint8_t r[S2N_KYBER_512_R3_POLYVECBYTES], const polyvec *a)
{
  unsigned int i;
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_tobytes_avx2(r+i*S2N_KYBER_512_R3_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes_avx2
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes_avx2
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                       - const polyvec *a: pointer to input vector of polynomials
*                                  (of length S2N_KYBER_512_R3_POLYVECBYTES)
**************************************************/
void polyvec_frombytes_avx2(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_frombytes_avx2(&r->vec[i], a+i*S2N_KYBER_512_R3_POLYBYTES);
}

/*************************************************
* Name:        polyvec_ntt_avx2
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt_avx2(polyvec *r)
{
  unsigned int i;
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_ntt_avx2(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt_tomont_avx2
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_tomont_avx2(polyvec *r)
{
  unsigned int i;
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_invntt_tomont_avx2(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_basemul_acc_montgomery_avx2
*
* Description: Multiply elements in a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_basemul_acc_montgomery_avx2(poly *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  poly tmp;

  poly_basemul_montgomery_avx2(r,&a->vec[0],&b->vec[0]);
  for(i=1;i<S2N_KYBER_512_R3_K;i++) {
    poly_basemul_montgomery_avx2(&tmp,&a->vec[i],&b->vec[i]);
    poly_add_avx2(r,r,&tmp);
  }
}

/*************************************************
* Name:        polyvec_reduce_avx2
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - polyvec *r: pointer to input/output polynomial
**************************************************/
void polyvec_reduce_avx2(polyvec *r)
{
  unsigned int i;
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_reduce_avx2(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add_avx2
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add_avx2(polyvec *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    poly_add_avx2(&r->vec[i], &a->vec[i], &b->vec[i]);
}
#endif
