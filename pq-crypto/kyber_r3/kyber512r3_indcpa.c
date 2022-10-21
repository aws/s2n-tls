#include <stddef.h>
#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_indcpa.h"
#include "kyber512r3_poly.h"
#include "kyber512r3_polyvec.h"
#include "kyber512r3_fips202.h"
#include "kyber512r3_symmetric.h"
#include "pq-crypto/s2n_pq_random.h"
#include "utils/s2n_safety.h"

S2N_ENSURE_PORTABLE_OPTIMIZATIONS

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r:          pointer to the output serialized public key
*              polyvec *pk:         pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES], polyvec *pk, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES]) {
    polyvec_tobytes(r, pk);
    for (size_t i = 0; i < S2N_KYBER_512_R3_SYMBYTES; i++) {
        r[i + S2N_KYBER_512_R3_POLYVECBYTES] = seed[i];
    }
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:             pointer to output public-key
*                                         polynomial vector
*              - uint8_t *seed:           pointer to output seed to generate
*                                         matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk, uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], const uint8_t packedpk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES]) {
    polyvec_frombytes(pk, packedpk);
    for (size_t i = 0; i < S2N_KYBER_512_R3_SYMBYTES; i++) {
        seed[i] = packedpk[i + S2N_KYBER_512_R3_POLYVECBYTES];
    }
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r:  pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:             pointer to output vector of
*                                         polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]) {
    polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk:   pointer to the input vector of polynomials b
*              poly *v:    pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[S2N_KYBER_512_R3_INDCPA_BYTES], polyvec *b, poly *v) {
    polyvec_compress(r, b);
    poly_compress(r + S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:       pointer to the output vector of polynomials b
*              - poly *v:          pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES]) {
    polyvec_decompress(b, c);
    poly_decompress(v, c + S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:          pointer to output buffer
*              - unsigned int len:    requested number of 16-bit integers
*                                     (uniform mod q)
*              - const uint8_t *buf:  pointer to input buffer
*                                     (assumed to be uniform random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr, pos;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint16_t val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        uint16_t  val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < S2N_KYBER_512_R3_Q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < S2N_KYBER_512_R3_Q) {
            r[ctr++] = val1;
        }
    }

    return ctr;
}

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:          pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed:      boolean deciding whether A or A^T
*                                     is generated
**************************************************/
#define XOF_BLOCKBYTES 168
#define GEN_MATRIX_NBLOCKS ((12*S2N_KYBER_512_R3_N/8*(1 << 12)/S2N_KYBER_512_R3_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
static void gen_matrix(polyvec *a, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], int transposed) {
    unsigned int ctr, buflen, off;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    xof_state state;

    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        for (unsigned int j = 0; j < S2N_KYBER_512_R3_K; j++) {
            if (transposed) {
                kyber_shake128_absorb(&state, seed, i, j);
            } else {
                kyber_shake128_absorb(&state, seed, j, i);
            }

            shake128_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, S2N_KYBER_512_R3_N, buf, buflen);

            while (ctr < S2N_KYBER_512_R3_N) {
                off = buflen % 3;
                for (unsigned int k = 0; k < off; k++) {
                    buf[k] = buf[buflen - off + k];
                }
                shake128_squeezeblocks(buf + off, 1, &state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, S2N_KYBER_512_R3_N - ctr, buf, buflen);
            }
        }
    }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                             (of length S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES bytes)
*
* Returns:     0 on success
*              !0 on failure
**************************************************/
int indcpa_keypair(uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES], uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]) {
    uint8_t buf[2 * S2N_KYBER_512_R3_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + S2N_KYBER_512_R3_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[S2N_KYBER_512_R3_K], e, pkpv, skpv;

    POSIX_GUARD_RESULT(s2n_get_random_bytes(buf, S2N_KYBER_512_R3_SYMBYTES));
    sha3_512(buf, buf, S2N_KYBER_512_R3_SYMBYTES);

    gen_matrix(a, publicseed, 0);

    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    //* matrix-vector multiplication */
    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        polyvec_pointwise_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);

    return 0;
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c:           pointer to output ciphertext
*                                      (of length S2N_KYBER_512_R3_INDCPA_BYTES bytes)
*              - const uint8_t *m:     pointer to input message
*                                      (of length S2N_KYBER_512_R3_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk:    pointer to input public key
*                                      (of length S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins
*                                      used as seed (of length S2N_KYBER_512_R3_SYMBYTES)
*                                      to deterministically generate all
*                                      randomness
**************************************************/
void indcpa_enc(uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES], const uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES],
        const uint8_t pk[S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES], const uint8_t coins[S2N_KYBER_512_R3_SYMBYTES]) {
    uint8_t seed[S2N_KYBER_512_R3_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[S2N_KYBER_512_R3_K], bp;
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_matrix(at, seed, 1);

    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_getnoise_eta1(sp.vec + i, coins, nonce++);
    }
    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    }
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    /* matrix-vector multiplication */
    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        polyvec_pointwise_acc_montgomery(&bp.vec[i], &at[i], &sp);
    }

    polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);

    polyvec_invntt_tomont(&bp);
    poly_invntt_tomont(&v);

    polyvec_add(&bp, &bp, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&bp);
    poly_reduce(&v);

    pack_ciphertext(c, &bp, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m:        pointer to output decrypted message
*                                   (of length S2N_KYBER_512_R3_INDCPA_MSGBYTES)
*              - const uint8_t *c:  pointer to input ciphertext
*                                   (of length S2N_KYBER_512_R3_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[S2N_KYBER_512_R3_INDCPA_MSGBYTES], const uint8_t c[S2N_KYBER_512_R3_INDCPA_BYTES],
        const uint8_t sk[S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES]) {
    polyvec bp, skpv;
    poly v, mp;

    unpack_ciphertext(&bp, &v, c);
    unpack_sk(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_pointwise_acc_montgomery(&mp, &skpv, &bp);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}
