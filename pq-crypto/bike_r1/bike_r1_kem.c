/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#include <string.h>

#include "decode.h"
#include "gf2x.h"
#include "parallel_hash.h"
#include "sampling.h"
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
merge_e(OUT e_t *e, IN const split_e_t *splitted_e)
{
  memcpy(e->raw, splitted_e->val[0].raw, R_SIZE);

  e->raw[R_SIZE - 1] = ((splitted_e->val[1].raw[0] << LAST_R_BYTE_LEAD) |
                        (e->raw[R_SIZE - 1] & LAST_R_BYTE_MASK));

  // Now load second value
  for(uint32_t i = 1; i < R_SIZE; ++i)
  {
    e->raw[R_SIZE + i - 1] =
        ((splitted_e->val[1].raw[i] << LAST_R_BYTE_LEAD) |
         (splitted_e->val[1].raw[i - 1] >> LAST_R_BYTE_TRAIL));
  }

  // Mask last byte
  if(N_SIZE == (2ULL * R_SIZE))
  {
    e->raw[N_SIZE - 1] =
        (splitted_e->val[1].raw[R_SIZE - 1] >> LAST_R_BYTE_TRAIL);
  }
}

_INLINE_ ret_t
encrypt(OUT ct_t *ct,
        IN const pk_t *pk,
        IN const seed_t *seed,
        IN const split_e_t *splitted_e)
{
  DEFER_CLEANUP(padded_r_t m = {0}, padded_r_cleanup);
  DEFER_CLEANUP(dbl_pad_ct_t p_ct, dbl_pad_ct_cleanup);

  // Pad the public key
  pad_pk_t p_pk = {0};
  p_pk[0].val   = pk->val[0];
  p_pk[1].val   = pk->val[1];

  DMSG("    Sampling m.\n");
  POSIX_GUARD(sample_uniform_r_bits(&m.val, seed, NO_RESTRICTION));

  DMSG("    Calculating the ciphertext.\n");

  POSIX_GUARD(gf2x_mod_mul((uint64_t *)&p_ct[0], (uint64_t *)&m, (uint64_t *)&p_pk[0]));
  POSIX_GUARD(gf2x_mod_mul((uint64_t *)&p_ct[1], (uint64_t *)&m, (uint64_t *)&p_pk[1]));

  DMSG("    Addding Error to the ciphertext.\n");

  POSIX_GUARD(
      gf2x_add(p_ct[0].val.raw, p_ct[0].val.raw, splitted_e->val[0].raw, R_SIZE));
  POSIX_GUARD(
      gf2x_add(p_ct[1].val.raw, p_ct[1].val.raw, splitted_e->val[1].raw, R_SIZE));

  // Copy the data outside
  ct->val[0] = p_ct[0].val;
  ct->val[1] = p_ct[1].val;

  print("m:  ", (uint64_t *)m.val.raw, R_BITS);
  print("c0: ", (uint64_t *)p_ct[0].val.raw, R_BITS);
  print("c1: ", (uint64_t *)p_ct[1].val.raw, R_BITS);

  return SUCCESS;
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

  print("g:  ", (uint64_t *)g.val.raw, R_BITS);
  print("g0: ", (uint64_t *)&p_pk[0], R_BITS);
  print("g1: ", (uint64_t *)&p_pk[1], R_BITS);

  return SUCCESS;
}

// Generate the Shared Secret (K(e))
_INLINE_ void
get_ss(OUT ss_t *out, IN const e_t *e)
{
  DMSG("    Enter get_ss.\n");

  // Calculate the hash
  DEFER_CLEANUP(sha_hash_t hash = {0}, sha_hash_cleanup);
  parallel_hash(&hash, e->raw, sizeof(*e));

  // Truncate the final hash into K by copying only the LSBs
  memcpy(out->raw, hash.u.raw, sizeof(*out));

  secure_clean(hash.u.raw, sizeof(hash));
  DMSG("    Exit get_ss.\n");
}

////////////////////////////////////////////////////////////////
// The three APIs below (keygeneration, encapsulate, decapsulate) are defined by
// NIST: In addition there are two KAT versions of this API as defined.
////////////////////////////////////////////////////////////////
int
BIKE1_L1_R1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk)
{
  POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

  // Convert to this implementation types
  pk_t *l_pk = (pk_t *)pk;

  DEFER_CLEANUP(ALIGN(8) sk_t l_sk = {0}, sk_cleanup);

  // For DRBG and AES_PRF
  DEFER_CLEANUP(seeds_t seeds = {0}, seeds_cleanup);
  DEFER_CLEANUP(aes_ctr_prf_state_t h_prf_state = {0}, aes_ctr_prf_state_cleanup);

  // Padded for internal use only (the padded data is not released).
  DEFER_CLEANUP(pad_sk_t p_sk = {0}, pad_sk_cleanup);

  // Get the entropy seeds.
  get_seeds(&seeds);

  DMSG("  Enter crypto_kem_keypair.\n");
  DMSG("    Calculating the secret key.\n");

  // h0 and h1 use the same context
  POSIX_GUARD(init_aes_ctr_prf_state(&h_prf_state, MAX_AES_INVOKATION, &seeds.seed[0]));

  POSIX_GUARD(generate_sparse_rep((uint64_t *)&p_sk[0], l_sk.wlist[0].val, DV, R_BITS,
                            sizeof(p_sk[0]), &h_prf_state));
  // Copy data
  l_sk.bin[0] = p_sk[0].val;

  POSIX_GUARD(generate_sparse_rep((uint64_t *)&p_sk[1], l_sk.wlist[1].val, DV, R_BITS,
                            sizeof(p_sk[1]), &h_prf_state));

  // Copy data
  l_sk.bin[1] = p_sk[1].val;

  DMSG("    Calculating the public key.\n");

  POSIX_GUARD(calc_pk(l_pk, &seeds.seed[1], p_sk));

  memcpy(sk, &l_sk, sizeof(l_sk));

  print("h0: ", (uint64_t *)&l_sk.bin[0], R_BITS);
  print("h1: ", (uint64_t *)&l_sk.bin[1], R_BITS);
  print("h0c:", (uint64_t *)&l_sk.wlist[0], SIZEOF_BITS(compressed_idx_dv_t));
  print("h1c:", (uint64_t *)&l_sk.wlist[1], SIZEOF_BITS(compressed_idx_dv_t));
  DMSG("  Exit crypto_kem_keypair.\n");

  return SUCCESS;
}

// Encapsulate - pk is the public key,
//               ct is a key encapsulation message (ciphertext),
//               ss is the shared secret.
int
BIKE1_L1_R1_crypto_kem_enc(OUT unsigned char *     ct,
                           OUT unsigned char *     ss,
                           IN const unsigned char *pk)
{
  DMSG("  Enter crypto_kem_enc.\n");
  POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

  // Convert to this implementation types
  const pk_t *l_pk = (const pk_t *)pk;
  ct_t *      l_ct = (ct_t *)ct;
  ss_t *      l_ss = (ss_t *)ss;
  DEFER_CLEANUP(padded_e_t e = {0}, padded_e_cleanup);

  // For NIST DRBG_CTR
  DEFER_CLEANUP(seeds_t seeds = {0}, seeds_cleanup);
  DEFER_CLEANUP(aes_ctr_prf_state_t e_prf_state = {0}, aes_ctr_prf_state_cleanup);

  // Get the entrophy seeds
  get_seeds(&seeds);

  // Random data generator
  // Using first seed
  POSIX_GUARD(init_aes_ctr_prf_state(&e_prf_state, MAX_AES_INVOKATION, &seeds.seed[0]));

  DMSG("    Generating error.\n");
  ALIGN(8) compressed_idx_t_t dummy;
  POSIX_GUARD(generate_sparse_rep((uint64_t *)&e, dummy.val, T1, N_BITS, sizeof(e),
                            &e_prf_state));

  print("e:  ", (uint64_t *)&e.val, sizeof(e) * 8);

  // Split e into e0 and e1. Initialization is done in split_e
  DEFER_CLEANUP(split_e_t splitted_e, split_e_cleanup);
  split_e(&splitted_e, &e.val);

  print("e0: ", (uint64_t *)splitted_e.val[0].raw, R_BITS);
  print("e1: ", (uint64_t *)splitted_e.val[1].raw, R_BITS);

  // Computing ct = enc(pk, e)
  // Using second seed
  DMSG("    Encrypting.\n");
  POSIX_GUARD(encrypt(l_ct, l_pk, &seeds.seed[1], &splitted_e));

  DMSG("    Generating shared secret.\n");
  get_ss(l_ss, &e.val);

  print("ss: ", (uint64_t *)l_ss->raw, SIZEOF_BITS(*l_ss));
  DMSG("  Exit crypto_kem_enc.\n");
  return SUCCESS;
}

// Decapsulate - ct is a key encapsulation message (ciphertext),
//               sk is the private key,
//               ss is the shared secret
int
BIKE1_L1_R1_crypto_kem_dec(OUT unsigned char *     ss,
                           IN const unsigned char *ct,
                           IN const unsigned char *sk)
{
  DMSG("  Enter crypto_kem_dec.\n");
  POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

  // Convert to this implementation types
  const ct_t *l_ct = (const ct_t *)ct;
  ss_t *      l_ss = (ss_t *)ss;

  DEFER_CLEANUP(ALIGN(8) sk_t l_sk, sk_cleanup);
  memcpy(&l_sk, sk, sizeof(l_sk));

  // Force zero initialization
  DEFER_CLEANUP(syndrome_t syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(split_e_t e, split_e_cleanup);
  DEFER_CLEANUP(e_t merged_e = {0}, e_cleanup);

  DMSG("  Computing s.\n");
  POSIX_GUARD(compute_syndrome(&syndrome, l_ct, &l_sk));

  DMSG("  Decoding.\n");
  POSIX_GUARD(decode(&e, &syndrome, l_ct, &l_sk));

  // Check if the error weight equals T1
  if(T1 != r_bits_vector_weight(&e.val[0]) + r_bits_vector_weight(&e.val[1]))
  {
    MSG("    Error weight is not t\n");
    BIKE_ERROR(E_ERROR_WEIGHT_IS_NOT_T);
  }

  merge_e(&merged_e, &e);
  get_ss(l_ss, &merged_e);

  DMSG("  Exit crypto_kem_dec.\n");
  return SUCCESS;
}
