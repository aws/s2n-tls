/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron, and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com, dkostic@amazon.com)
 */

#include "decode.h"
#include "gf2x.h"
#include "sampling.h"
#include "sha.h"
#include "tls/s2n_kem.h"
#include "pq-crypto/s2n_pq.h"

_INLINE_ void
split_e(OUT split_e_t *splitted_e, IN const e_t *e)
{
  // Copy lower bytes (e0)
  memcpy(splitted_e->val[0].raw, e->raw, R_SIZE);

  // Now load second value
  for(uint32_t i = R_SIZE; i < N_SIZE; ++i)
  {
    splitted_e->val[1].raw[i - R_SIZE] =
        ((e->raw[i] << LAST_R_BYTE_TRAIL) | (e->raw[i - 1] >> LAST_R_BYTE_LEAD));
  }

  // Fix corner case
  if(N_SIZE < (2ULL * R_SIZE))
  {
    splitted_e->val[1].raw[R_SIZE - 1] = (e->raw[N_SIZE - 1] >> LAST_R_BYTE_LEAD);
  }

  // Fix last value
  splitted_e->val[0].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
  splitted_e->val[1].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
}

_INLINE_ void
translate_hash_to_ss(OUT ss_t *ss, IN sha_hash_t *hash)
{
  bike_static_assert(sizeof(*hash) >= sizeof(*ss), hash_size_lt_ss_size);
  memcpy(ss->raw, hash->u.raw, sizeof(*ss));
}

_INLINE_ void
translate_hash_to_seed(OUT seed_t *seed, IN sha_hash_t *hash)
{
  bike_static_assert(sizeof(*hash) >= sizeof(*seed), hash_size_lt_seed_size);
  memcpy(seed->raw, hash->u.raw, sizeof(*seed));
}

_INLINE_ ret_t
calc_pk(OUT pk_t *pk, IN const seed_t *g_seed, IN const pad_sk_t p_sk)
{
  // PK is dbl padded because modmul require some scratch space for the
  // multiplication result
  dbl_pad_pk_t p_pk = {0};

  // Intialized padding to zero
  DEFER_CLEANUP(padded_r_t g = {0}, padded_r_cleanup);

  POSIX_GUARD(sample_uniform_r_bits(&g.val, g_seed, MUST_BE_ODD));

  // Calculate (g0, g1) = (g*h1, g*h0)
  POSIX_GUARD(gf2x_mod_mul((uint64_t *)&p_pk[0], (const uint64_t *)&g,
                     (const uint64_t *)&p_sk[1]));
  POSIX_GUARD(gf2x_mod_mul((uint64_t *)&p_pk[1], (const uint64_t *)&g,
                     (const uint64_t *)&p_sk[0]));

  // Copy the data to the output parameters.
  pk->val[0] = p_pk[0].val;
  pk->val[1] = p_pk[1].val;

  print("g:  ", (const uint64_t *)g.val.raw, R_BITS);
  print("g0: ", (const uint64_t *)&p_pk[0], R_BITS);
  print("g1: ", (uint64_t *)&p_pk[1], R_BITS);

  return SUCCESS;
}

// The function H is required by BIKE-1- Round 2 variant. It uses the
// extract-then-expand paradigm, based on SHA384 and AES256-CTR PRNG, to produce
// e from (m*f0, m*f1):
_INLINE_ ret_t
function_h(OUT split_e_t *splitted_e, IN const r_t *in0, IN const r_t *in1)
{
  DEFER_CLEANUP(generic_param_n_t tmp, generic_param_n_cleanup);
  DEFER_CLEANUP(sha_hash_t hash_seed = {0}, sha_hash_cleanup);
  DEFER_CLEANUP(seed_t seed_for_hash, seed_cleanup);
  DEFER_CLEANUP(aes_ctr_prf_state_t prf_state = {0}, finalize_aes_ctr_prf);

  tmp.val[0] = *in0;
  tmp.val[1] = *in1;

  // Hash (m*f0, m*f1) to generate a seed:
  sha(&hash_seed, sizeof(tmp), (uint8_t *)&tmp);

  // Format the seed as a 32-bytes input:
  translate_hash_to_seed(&seed_for_hash, &hash_seed);

  // Use the seed to generate a sparse error vector e:
  DMSG("    Generating random error.\n");
  POSIX_GUARD(init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, &seed_for_hash));

  DEFER_CLEANUP(padded_e_t e, padded_e_cleanup);
  DEFER_CLEANUP(ALIGN(8) compressed_idx_t_t dummy, compressed_idx_t_cleanup);

  POSIX_GUARD(generate_sparse_rep((uint64_t *)&e, dummy.val, T1, N_BITS, sizeof(e),
                            &prf_state));
  split_e(splitted_e, &e.val);

  return SUCCESS;
}

_INLINE_ ret_t
encrypt(OUT ct_t *ct, OUT split_e_t *mf, IN const pk_t *pk, IN const seed_t *seed)
{
  DEFER_CLEANUP(padded_r_t m = {0}, padded_r_cleanup);

  DMSG("    Sampling m.\n");
  POSIX_GUARD(sample_uniform_r_bits(&m.val, seed, NO_RESTRICTION));

  // Pad the public key
  pad_pk_t p_pk = {0};
  p_pk[0].val   = pk->val[0];
  p_pk[1].val   = pk->val[1];

  // Pad the ciphertext
  pad_ct_t p_ct = {0};
  p_ct[0].val   = ct->val[0];
  p_ct[1].val   = ct->val[1];

  DEFER_CLEANUP(dbl_pad_ct_t mf_int = {0}, dbl_pad_ct_cleanup);

  DMSG("    Computing m*f0 and m*f1.\n");
  POSIX_GUARD(
      gf2x_mod_mul((uint64_t *)&mf_int[0], (uint64_t *)&m, (uint64_t *)&p_pk[0]));
  POSIX_GUARD(
      gf2x_mod_mul((uint64_t *)&mf_int[1], (uint64_t *)&m, (uint64_t *)&p_pk[1]));

  DEFER_CLEANUP(split_e_t splitted_e, split_e_cleanup);

  DMSG("    Computing the hash function e <- H(m*f0, m*f1).\n");
  POSIX_GUARD(function_h(&splitted_e, &mf_int[0].val, &mf_int[1].val));

  DMSG("    Addding Error to the ciphertext.\n");
  POSIX_GUARD(gf2x_add(p_ct[0].val.raw, mf_int[0].val.raw, splitted_e.val[0].raw,
                 R_SIZE));
  POSIX_GUARD(gf2x_add(p_ct[1].val.raw, mf_int[1].val.raw, splitted_e.val[1].raw,
                 R_SIZE));

  // Copy the data to the output parameters.
  ct->val[0] = p_ct[0].val;
  ct->val[1] = p_ct[1].val;

  // Copy the internal mf to the output parameters.
  mf->val[0] = mf_int[0].val;
  mf->val[1] = mf_int[1].val;

  print("e0: ", (uint64_t *)splitted_e.val[0].raw, R_BITS);
  print("e1: ", (uint64_t *)splitted_e.val[1].raw, R_BITS);
  print("c0: ", (uint64_t *)p_ct[0].val.raw, R_BITS);
  print("c1: ", (uint64_t *)p_ct[1].val.raw, R_BITS);

  return SUCCESS;
}

_INLINE_ ret_t
reencrypt(OUT pad_ct_t ce,
          OUT split_e_t *e2,
          IN const split_e_t *e,
          IN const ct_t *l_ct)
{
  // Compute (c0 + e0') and (c1 + e1')
  POSIX_GUARD(gf2x_add(ce[0].val.raw, l_ct->val[0].raw, e->val[0].raw, R_SIZE));
  POSIX_GUARD(gf2x_add(ce[1].val.raw, l_ct->val[1].raw, e->val[1].raw, R_SIZE));

  // (e0'', e1'') <-- H(c0 + e0', c1 + e1')
  POSIX_GUARD(function_h(e2, &ce[0].val, &ce[1].val));

  return SUCCESS;
}

// Generate the Shared Secret K(mf0, mf1, c) by either
// K(c0+e0', c1+e1', c) or K(sigma0, sigma1, c)
_INLINE_ void
get_ss(OUT ss_t *out, IN const r_t *in0, IN const r_t *in1, IN const ct_t *ct)
{
  DMSG("    Enter get_ss.\n");

  uint8_t tmp[4 * R_SIZE];
  memcpy(tmp, in0->raw, R_SIZE);
  memcpy(tmp + R_SIZE, in1->raw, R_SIZE);
  memcpy(tmp + 2 * R_SIZE, ct, sizeof(*ct));

  // Calculate the hash digest
  DEFER_CLEANUP(sha_hash_t hash = {0}, sha_hash_cleanup);
  sha(&hash, sizeof(tmp), tmp);

  // Truncate the resulting digest, to produce the key K, by copying only the
  // desired number of LSBs.
  translate_hash_to_ss(out, &hash);

  secure_clean(tmp, sizeof(tmp));
  DMSG("    Exit get_ss.\n");
}
////////////////////////////////////////////////////////////////////////////////
// The three APIs below (keypair, encapsulate, decapsulate) are defined by NIST:
////////////////////////////////////////////////////////////////////////////////
int
BIKE1_L1_R2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk)
{
  POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

  POSIX_ENSURE_REF(sk);
  POSIX_ENSURE_REF(pk);

  // Convert to this implementation types
  pk_t *l_pk = (pk_t *)pk;
  DEFER_CLEANUP(ALIGN(8) sk_t l_sk = {0}, sk_cleanup);

  // For DRBG and AES_PRF
  DEFER_CLEANUP(seeds_t seeds = {0}, seeds_cleanup);
  DEFER_CLEANUP(aes_ctr_prf_state_t h_prf_state = {0}, aes_ctr_prf_state_cleanup);

  // For sigma0/1/2
  DEFER_CLEANUP(aes_ctr_prf_state_t s_prf_state = {0}, aes_ctr_prf_state_cleanup);

  // Padded for internal use only (the padded data is not released).
  DEFER_CLEANUP(pad_sk_t p_sk = {0}, pad_sk_cleanup);

  // Get the entropy seeds.
  POSIX_GUARD(get_seeds(&seeds));

  DMSG("  Enter crypto_kem_keypair.\n");
  DMSG("    Calculating the secret key.\n");

  // h0 and h1 use the same context
  POSIX_GUARD(init_aes_ctr_prf_state(&h_prf_state, MAX_AES_INVOKATION, &seeds.seed[0]));

  // sigma0/1/2 use the same context.
  POSIX_GUARD(init_aes_ctr_prf_state(&s_prf_state, MAX_AES_INVOKATION, &seeds.seed[2]));

  POSIX_GUARD(generate_sparse_rep((uint64_t *)&p_sk[0], l_sk.wlist[0].val, DV, R_BITS,
                            sizeof(p_sk[0]), &h_prf_state));

  // Sample the sigmas
  POSIX_GUARD(sample_uniform_r_bits_with_fixed_prf_context(&l_sk.sigma0, &s_prf_state,
                                                     NO_RESTRICTION));
  POSIX_GUARD(sample_uniform_r_bits_with_fixed_prf_context(&l_sk.sigma1, &s_prf_state,
                                                     NO_RESTRICTION));

  POSIX_GUARD(generate_sparse_rep((uint64_t *)&p_sk[1], l_sk.wlist[1].val, DV, R_BITS,
                            sizeof(p_sk[1]), &h_prf_state));

  // Copy data
  l_sk.bin[0] = p_sk[0].val;
  l_sk.bin[1] = p_sk[1].val;

  DMSG("    Calculating the public key.\n");

  POSIX_GUARD(calc_pk(l_pk, &seeds.seed[1], p_sk));

  memcpy(sk, &l_sk, sizeof(l_sk));

  print("h0: ", (uint64_t *)&l_sk.bin[0], R_BITS);
  print("h1: ", (uint64_t *)&l_sk.bin[1], R_BITS);
  print("h0c:", (uint64_t *)&l_sk.wlist[0], SIZEOF_BITS(compressed_idx_dv_t));
  print("h1c:", (uint64_t *)&l_sk.wlist[1], SIZEOF_BITS(compressed_idx_dv_t));
  print("sigma0: ", (uint64_t *)l_sk.sigma0.raw, R_BITS);
  print("sigma1: ", (uint64_t *)l_sk.sigma1.raw, R_BITS);

  DMSG("  Exit crypto_kem_keypair.\n");

  return SUCCESS;
}

// Encapsulate - pk is the public key,
//               ct is a key encapsulation message (ciphertext),
//               ss is the shared secret.
int
BIKE1_L1_R2_crypto_kem_enc(OUT unsigned char *     ct,
                           OUT unsigned char *     ss,
                           IN const unsigned char *pk)
{
  DMSG("  Enter crypto_kem_enc.\n");
  POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

  // Convert to the types that are used by this implementation
  const pk_t *l_pk = (const pk_t *)pk;
  ct_t *      l_ct = (ct_t *)ct;
  ss_t *      l_ss = (ss_t *)ss;

  POSIX_ENSURE_REF(pk);
  POSIX_ENSURE_REF(ct);
  POSIX_ENSURE_REF(ss);

  // For NIST DRBG_CTR
  DEFER_CLEANUP(seeds_t seeds = {0}, seeds_cleanup);

  // Get the entropy seeds.
  POSIX_GUARD(get_seeds(&seeds));

  DMSG("    Encrypting.\n");
  // In fact, seed[0] should be used.
  // Here, we stay consistent with BIKE's reference code
  // that chooses the seconde seed.
  DEFER_CLEANUP(split_e_t mf, split_e_cleanup);
  POSIX_GUARD(encrypt(l_ct, &mf, l_pk, &seeds.seed[1]));

  DMSG("    Generating shared secret.\n");
  get_ss(l_ss, &mf.val[0], &mf.val[1], l_ct);

  print("ss: ", (uint64_t *)l_ss->raw, SIZEOF_BITS(*l_ss));
  DMSG("  Exit crypto_kem_enc.\n");
  return SUCCESS;
}

// Decapsulate - ct is a key encapsulation message (ciphertext),
//               sk is the private key,
//               ss is the shared secret
int
BIKE1_L1_R2_crypto_kem_dec(OUT unsigned char *     ss,
                           IN const unsigned char *ct,
                           IN const unsigned char *sk)
{
  DMSG("  Enter crypto_kem_dec.\n");
  POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

  // Convert to the types used by this implementation
  const ct_t *l_ct = (const ct_t *)ct;
  ss_t *      l_ss = (ss_t *)ss;
  POSIX_ENSURE_REF(sk);
  POSIX_ENSURE_REF(ct);
  POSIX_ENSURE_REF(ss);

  DEFER_CLEANUP(ALIGN(8) sk_t l_sk, sk_cleanup);
  memcpy(&l_sk, sk, sizeof(l_sk));

  // Force zero initialization.
  DEFER_CLEANUP(syndrome_t syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(split_e_t e, split_e_cleanup);

  DMSG("  Computing s.\n");
  POSIX_GUARD(compute_syndrome(&syndrome, l_ct, &l_sk));

  DMSG("  Decoding.\n");
  uint32_t dec_ret = decode(&e, &syndrome, l_ct, &l_sk) != SUCCESS ? 0 : 1;

  DEFER_CLEANUP(split_e_t e2, split_e_cleanup);
  DEFER_CLEANUP(pad_ct_t ce, pad_ct_cleanup);
  POSIX_GUARD(reencrypt(ce, &e2, &e, l_ct));

  // Check if the decoding is successful.
  // Check if the error weight equals T1.
  // Check if (e0', e1') == (e0'', e1'').
  volatile uint32_t success_cond;
  success_cond = dec_ret;
  success_cond &= secure_cmp32(T1, r_bits_vector_weight(&e.val[0]) +
                                       r_bits_vector_weight(&e.val[1]));
  success_cond &= secure_cmp((uint8_t *)&e, (uint8_t *)&e2, sizeof(e));

  ss_t ss_succ = {0};
  ss_t ss_fail = {0};

  get_ss(&ss_succ, &ce[0].val, &ce[1].val, l_ct);
  get_ss(&ss_fail, &l_sk.sigma0, &l_sk.sigma1, l_ct);

  uint8_t mask = ~secure_l32_mask(0, success_cond);
  for(uint32_t i = 0; i < sizeof(*l_ss); i++)
  {
    l_ss->raw[i] = (mask & ss_succ.raw[i]) | (~mask & ss_fail.raw[i]);
  }

  DMSG("  Exit crypto_kem_dec.\n");
  return SUCCESS;
}
