#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kyber512r3_align_avx2.h"
#include "kyber512r3_params.h"
#include "kyber512r3_indcpa_avx2.h"
#include "kyber512r3_polyvec_avx2.h"
#include "kyber512r3_poly_avx2.h"
#include "kyber512r3_rejsample_avx2.h"
#include "kyber512r3_fips202.h"
#include "kyber512r3_fips202x4_avx2.h"
#include "pq-crypto/s2n_pq_random.h"
#include "utils/s2n_safety.h"

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#include <immintrin.h>

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk and the
*              public seed used to generate the matrix A.
*              The polynomial coefficients in pk are assumed to
*              lie in the invertal [0,q], i.e. pk must be reduced
*              by polyvec_reduce_avx2().
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES])
{
  polyvec_tobytes_avx2(r, pk);
  memcpy(r+S2N_KYBER_512_R3_POLYVECBYTES, seed, S2N_KYBER_512_R3_SYMBYTES);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[S2N_KYBER_512_R3_SYMBYTES],
                      const uint8_t packedpk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes_avx2(pk, packedpk);
  memcpy(seed, packedpk+S2N_KYBER_512_R3_POLYVECBYTES, S2N_KYBER_512_R3_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key.
*              The polynomial coefficients in sk are assumed to
*              lie in the invertal [0,q], i.e. sk must be reduced
*              by polyvec_reduce_avx2().
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes_avx2(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes_avx2(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v.
*              The polynomial coefficients in b and v are assumed to
*              lie in the invertal [0,q], i.e. b and v must be reduced
*              by polyvec_reduce_avx2() and poly_reduce_avx2(), respectively.
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[S2N_KYBER_512_R3_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress_avx2(r, b);
  poly_compress_avx2(r+S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES])
{
  polyvec_decompress_avx2(b, c);
  poly_decompress_avx2(v, c+S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output array
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < S2N_KYBER_512_R3_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < S2N_KYBER_512_R3_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix_avx2(A,B,0)
#define gen_at(A,B) gen_matrix_avx2(A,B,1)

/*************************************************
* Name:        gen_matrix_avx2
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
void gen_matrix_avx2(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(S2N_KYBER_512_R3_REJ_UNIFORM_AVX_NBLOCKS*S2N_KYBER_512_R3_SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  // correcting cast-align and cast-qual errors
  // old version: f = _mm256_loadu_si256((__m256i *)seed);
  f = _mm256_loadu_si256((const void *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 1;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 1;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, S2N_KYBER_512_R3_REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx2(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx2(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx2(a[1].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx2(a[1].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < S2N_KYBER_512_R3_N || ctr1 < S2N_KYBER_512_R3_N || ctr2 < S2N_KYBER_512_R3_N || ctr3 < S2N_KYBER_512_R3_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, S2N_KYBER_512_R3_N - ctr0, buf[0].coeffs, S2N_KYBER_512_R3_SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, S2N_KYBER_512_R3_N - ctr1, buf[1].coeffs, S2N_KYBER_512_R3_SHAKE128_RATE);
    ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, S2N_KYBER_512_R3_N - ctr2, buf[2].coeffs, S2N_KYBER_512_R3_SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, S2N_KYBER_512_R3_N - ctr3, buf[3].coeffs, S2N_KYBER_512_R3_SHAKE128_RATE);
  }

  poly_nttunpack_avx2(&a[0].vec[0]);
  poly_nttunpack_avx2(&a[0].vec[1]);
  poly_nttunpack_avx2(&a[1].vec[0]);
  poly_nttunpack_avx2(&a[1].vec[1]);
}

/*************************************************
* Name:        indcpa_keypair_avx2
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
int indcpa_keypair_avx2(uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES])
{
  unsigned int i;
  uint8_t buf[2*S2N_KYBER_512_R3_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf + S2N_KYBER_512_R3_SYMBYTES;
  polyvec a[S2N_KYBER_512_R3_K], e, pkpv, skpv;

  POSIX_GUARD_RESULT(s2n_get_random_bytes(buf, S2N_KYBER_512_R3_SYMBYTES));
  sha3_512(buf, buf, S2N_KYBER_512_R3_SYMBYTES);

  gen_a(a, publicseed);

  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, e.vec+0, e.vec+1, noiseseed, 0, 1, 2, 3);

  polyvec_ntt_avx2(&skpv);
  polyvec_reduce_avx2(&skpv);
  polyvec_ntt_avx2(&e);

  // matrix-vector multiplication
  for(i=0;i<S2N_KYBER_512_R3_K;i++) {
    polyvec_basemul_acc_montgomery_avx2(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont_avx2(&pkpv.vec[i]);
  }

  polyvec_add_avx2(&pkpv, &pkpv, &e);
  polyvec_reduce_avx2(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

  return 0;
}

/*************************************************
* Name:        indcpa_enc_avx2
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length S2N_KYBER_512_R3_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length S2N_KYBER_512_R3_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length S2N_KYBER_512_R3_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc_avx2(uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES],
                const uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES],
                const uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[S2N_KYBER_512_R3_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[S2N_KYBER_512_R3_SYMBYTES];
  polyvec sp, pkpv, ep, at[S2N_KYBER_512_R3_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg_avx2(&k, m);
  gen_at(at, seed);

  poly_getnoise_eta1122_4x(sp.vec+0, sp.vec+1, ep.vec+0, ep.vec+1, coins, 0, 1, 2, 3);
  poly_getnoise_eta2_avx2(&epp, coins, 4);

  polyvec_ntt_avx2(&sp);

  // matrix-vector multiplication
  for(i=0;i<S2N_KYBER_512_R3_K;i++)
    polyvec_basemul_acc_montgomery_avx2(&b.vec[i], &at[i], &sp);
  polyvec_basemul_acc_montgomery_avx2(&v, &pkpv, &sp);

  polyvec_invntt_tomont_avx2(&b);
  poly_invntt_tomont_avx2(&v);

  polyvec_add_avx2(&b, &b, &ep);
  poly_add_avx2(&v, &v, &epp);
  poly_add_avx2(&v, &v, &k);
  polyvec_reduce_avx2(&b);
  poly_reduce_avx2(&v);

  pack_ciphertext(c, &b, &v);
}

/*************************************************
* Name:        indcpa_dec_avx2
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length S2N_KYBER_512_R3_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length S2N_KYBER_512_R3_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec_avx2(uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES],
                const uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES],
                const uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt_avx2(&b);
  polyvec_basemul_acc_montgomery_avx2(&mp, &skpv, &b);
  poly_invntt_tomont_avx2(&mp);

  poly_sub_avx2(&mp, &v, &mp);
  poly_reduce_avx2(&mp);

  poly_tomsg_avx2(m, &mp);
}
#endif
