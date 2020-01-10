/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * The license is detailed in the file LICENSE.md, and applies to this file.
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#include <string.h>

#include "bike_r1_kem.h"
#include "decode.h"
#include "gf2x.h"
#include "parallel_hash.h"
#include "sampling.h"

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
  VAL(p_pk[0])  = PTRV(pk)[0];
  VAL(p_pk[1])  = PTRV(pk)[1];

  DMSG("    Sampling m.\n");
  GUARD(sample_uniform_r_bits(VAL(m).raw, seed, NO_RESTRICTION));

  EDMSG("m:  ");
  print((uint64_t *)VAL(m).raw, R_BITS);

  DMSG("    Calculating the ciphertext.\n");

  GUARD(gf2x_mod_mul(p_ct[0].u.qw, m.u.qw, p_pk[0].u.qw));
  GUARD(gf2x_mod_mul(p_ct[1].u.qw, m.u.qw, p_pk[1].u.qw));

  DMSG("    Addding Error to the ciphertext.\n");

  GUARD(gf2x_add(VAL(p_ct[0]).raw, VAL(p_ct[0]).raw, PTRV(splitted_e)[0].raw,
                 R_SIZE));
  GUARD(gf2x_add(VAL(p_ct[1]).raw, VAL(p_ct[1]).raw, PTRV(splitted_e)[1].raw,
                 R_SIZE));

  // Copy the data outside
  PTRV(ct)[0] = VAL(p_ct[0]);
  PTRV(ct)[1] = VAL(p_ct[1]);

  EDMSG("c0: ");
  print((uint64_t *)PTRV(ct)[0].raw, R_BITS);
  EDMSG("c1: ");
  print((uint64_t *)PTRV(ct)[1].raw, R_BITS);

  return SUCCESS;
}

_INLINE_ ret_t
calc_pk(OUT pk_t *pk, IN const seed_t *g_seed, IN const pad_sk_t p_sk)
{
  // PK is dbl padded because modmul require scratch space for the multiplication
  // result
  dbl_pad_pk_t p_pk = {0};

  // Must intialized padding to zero!!
  DEFER_CLEANUP(padded_r_t g = {0}, padded_r_cleanup);
  GUARD(sample_uniform_r_bits(VAL(g).raw, g_seed, MUST_BE_ODD));

  EDMSG("g:  ");
  print((uint64_t *)VAL(g).raw, R_BITS);

  // Calculate (g0, g1) = (g*h1, g*h0)
  GUARD(gf2x_mod_mul(p_pk[0].u.qw, g.u.qw, p_sk[1].u.qw));
  GUARD(gf2x_mod_mul(p_pk[1].u.qw, g.u.qw, p_sk[0].u.qw));

  // Copy the data outside
  PTRV(pk)[0] = VAL(p_pk[0]);
  PTRV(pk)[1] = VAL(p_pk[1]);

  EDMSG("g0: ");
  print((uint64_t *)PTRV(pk)[0].raw, R_BITS);
  EDMSG("g1: ");
  print((uint64_t *)PTRV(pk)[1].raw, R_BITS);

  return SUCCESS;
}

// Generate the Shared Secret (K(e))
_INLINE_ void
get_ss(OUT ss_t *out, IN const e_t *e)
{
  DMSG("    Enter get_ss.\n");

  // Calculate the hash
  sha_hash_t hash = {0};
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
  // Convert to this implementation types
  sk_t *l_sk = (sk_t *)sk;
  pk_t *l_pk = (pk_t *)pk;

  // For DRBG and AES_PRF
  DEFER_CLEANUP(double_seed_t seeds = {0}, double_seed_cleanup);
  DEFER_CLEANUP(aes_ctr_prf_state_t h_prf_state = {0}, aes_ctr_prf_state_cleanup);
  // Padded for internal use
  // We don't want to send the padded data outside to save BW.
  DEFER_CLEANUP(pad_sk_t p_sk = {0}, pad_sk_cleanup);

  // Get the entrophy seeds
  GUARD(get_seeds(&seeds));

  DMSG("  Enter crypto_kem_keypair.\n");
  DMSG("    Calculating the secret key.\n");

  // Both h0 and h1 use the same context
  GUARD(init_aes_ctr_prf_state(&h_prf_state, MAX_AES_INVOKATION, &seeds.u.v.s1));

  // Make sure that the wlists are zeroed for the KATs.
  memset(l_sk, 0, sizeof(sk_t));
  GUARD(generate_sparse_fake_rep(p_sk[0].u.qw, PTR(l_sk).wlist[0].val,
                                 sizeof(p_sk[0]), &h_prf_state));
  // Copy data
  PTR(l_sk).bin[0] = VAL(p_sk[0]);

  GUARD(generate_sparse_fake_rep(p_sk[1].u.qw, PTR(l_sk).wlist[1].val,
                                 sizeof(p_sk[1]), &h_prf_state));

  // Copy data
  PTR(l_sk).bin[1] = VAL(p_sk[1]);

  DMSG("    Calculating the public key.\n");

  GUARD(calc_pk(l_pk, &seeds.u.v.s2, p_sk));

  EDMSG("h0: ");
  print((uint64_t *)&PTR(l_sk).bin[0], R_BITS);
  EDMSG("h1: ");
  print((uint64_t *)&PTR(l_sk).bin[1], R_BITS);
  EDMSG("h0c:");
  print((uint64_t *)&PTR(l_sk).wlist[0], SIZEOF_BITS(compressed_idx_dv_t));
  EDMSG("h1c:");
  print((uint64_t *)&PTR(l_sk).wlist[1], SIZEOF_BITS(compressed_idx_dv_t));
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

  // Convert to this implementation types
  const pk_t *l_pk = (const pk_t *)pk;
  ct_t *      l_ct = (ct_t *)ct;
  ss_t *      l_ss = (ss_t *)ss;
  DEFER_CLEANUP(padded_e_t e = {0}, padded_e_cleanup);

  // For NIST DRBG_CTR
  DEFER_CLEANUP(double_seed_t seeds = {0}, double_seed_cleanup);
  DEFER_CLEANUP(aes_ctr_prf_state_t e_prf_state = {0}, aes_ctr_prf_state_cleanup);

  // Get the entrophy seeds
  GUARD(get_seeds(&seeds));

  // Random data generator
  // Using first seed
  GUARD(init_aes_ctr_prf_state(&e_prf_state, MAX_AES_INVOKATION, &seeds.u.v.s1));

  DMSG("    Generating error.\n");
  compressed_idx_t_t dummy;
  GUARD(generate_sparse_rep(e.u.qw, dummy.val, T1, N_BITS, sizeof(e),
                            &e_prf_state));

  EDMSG("e:  ");
  print((uint64_t *)VAL(e).raw, sizeof(e) * 8);

  // Split e into e0 and e1. Initialization is done in split_e
  DEFER_CLEANUP(split_e_t splitted_e, split_e_cleanup);
  split_e(&splitted_e, &VAL(e));

  EDMSG("e0: ");
  print((uint64_t *)VAL(splitted_e)[0].raw, R_BITS);
  EDMSG("e1: ");
  print((uint64_t *)VAL(splitted_e)[1].raw, R_BITS);

  // Computing ct = enc(pk, e)
  // Using second seed
  DMSG("    Encrypting.\n");
  GUARD(encrypt(l_ct, l_pk, &seeds.u.v.s2, &splitted_e));

  DMSG("    Generating shared secret.\n");
  get_ss(l_ss, &VAL(e));

  EDMSG("ss: ");
  print((uint64_t *)l_ss->raw, SIZEOF_BITS(*l_ss));
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

  // Convert to this implementation types
  const sk_t *l_sk = (const sk_t *)sk;
  const ct_t *l_ct = (const ct_t *)ct;
  ss_t *      l_ss = (ss_t *)ss;

  // Force zero initialization
  DEFER_CLEANUP(syndrome_t syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(e_t e = {0}, e_cleanup);

  DMSG("  Computing s.\n");
  GUARD(compute_syndrome(&syndrome, l_ct, l_sk));

  DMSG("  Decoding.\n");
  GUARD(decode(&e, &syndrome, l_ct, l_sk, U_ERR));

  // Check if the error weight equals T1
  if(count_ones(e.raw, sizeof(e)) != T1)
  {
    MSG("    Error weight is not t\n");
    BIKE_ERROR(E_ERROR_WEIGHT_IS_NOT_T);
  }

  get_ss(l_ss, &e);

  DMSG("  Exit crypto_kem_dec.\n");
  return SUCCESS;
}
