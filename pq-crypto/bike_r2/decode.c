/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
 * Written by Nir Drucker, Shay Gueron, and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com, dkostic@amazon.com)
 *
 * [1] The optimizations are based on the description developed in the paper:
 *     Drucker, Nir, and Shay Gueron. 2019. “A Toolbox for Software Optimization
 *     of QC-MDPC Code-Based Cryptosystems.” Journal of Cryptographic Engineering,
 *     January, 1–17. https://doi.org/10.1007/s13389-018-00200-4.
 *
 * [2] The decoder algorithm is the Black-Gray decoder in
 *     the early submission of CAKE (due to N. Sandrier and R Misoczki).
 *
 * [3] The analysis for the constant time implementation is given in
 *     Drucker, Nir, Shay Gueron, and Dusan Kostic. 2019.
 *     “On Constant-Time QC-MDPC Decoding with Negligible Failure Rate.”
 *     Cryptology EPrint Archive, 2019. https://eprint.iacr.org/2019/1289.
 *
 * [4] it was adapted to BGF in:
 *     Drucker, Nir, Shay Gueron, and Dusan Kostic. 2019.
 *     “QC-MDPC decoders with several shades of gray.”
 *     Cryptology EPrint Archive, 2019. To be published.
 *
 * [5] Chou, T.: QcBits: Constant-Time Small-Key Code-Based Cryptography.
 *     In: Gier-lichs, B., Poschmann, A.Y. (eds.) Cryptographic Hardware
 *     and Embedded Systems– CHES 2016. pp. 280–300. Springer Berlin Heidelberg,
 *     Berlin, Heidelberg (2016)
 *
 * [6] The rotate512_small funciton is a derivative of the code described in:
 *     Guimarães, Antonio, Diego F Aranha, and Edson Borin. 2019.
 *     “Optimized Implementation of QC-MDPC Code-Based Cryptography.”
 *     Concurrency and Computation: Practice and Experience 31 (18):
 *     e5089. https://doi.org/10.1002/cpe.5089.
 */

#include "decode.h"
#include "gf2x.h"
#include "utilities.h"
#include <string.h>

// Decoding (bit-flipping) parameter
#ifdef BG_DECODER
#  if(LEVEL == 1)
#    define MAX_IT 3
#  elif(LEVEL == 3)
#    define MAX_IT 4
#  elif(LEVEL == 5)
#    define MAX_IT 7
#  else
#    error "Level can only be 1/3/5"
#  endif
#elif defined(BGF_DECODER)
#  if(LEVEL == 1)
#    define MAX_IT 5
#  elif(LEVEL == 3)
#    define MAX_IT 6
#  elif(LEVEL == 5)
#    define MAX_IT 7
#  else
#    error "Level can only be 1/3/5"
#  endif
#endif

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
_INLINE_ void
dup(IN OUT syndrome_t *s)
{
  s->qw[R_QW - 1] =
      (s->qw[0] << LAST_R_QW_LEAD) | (s->qw[R_QW - 1] & LAST_R_QW_MASK);

  for(size_t i = 0; i < (2 * R_QW) - 1; i++)
  {
    s->qw[R_QW + i] =
        (s->qw[i] >> LAST_R_QW_TRAIL) | (s->qw[i + 1] << LAST_R_QW_LEAD);
  }
}

ret_t
compute_syndrome(OUT syndrome_t *syndrome, IN const ct_t *ct, IN const sk_t *sk)
{
  // gf2x_mod_mul requires the values to be 64bit padded and extra (dbl) space
  // for the results
  DEFER_CLEANUP(dbl_pad_syndrome_t pad_s, dbl_pad_syndrome_cleanup);
  DEFER_CLEANUP(pad_sk_t pad_sk = {0}, pad_sk_cleanup);
  pad_sk[0].val = sk->bin[0];
  pad_sk[1].val = sk->bin[1];

  DEFER_CLEANUP(pad_ct_t pad_ct = {0}, pad_ct_cleanup);
  pad_ct[0].val = ct->val[0];
  pad_ct[1].val = ct->val[1];

  // Compute s = c0*h0 + c1*h1:
  GUARD(gf2x_mod_mul((uint64_t *)&pad_s[0], (uint64_t *)&pad_ct[0],
                     (uint64_t *)&pad_sk[0]));
  GUARD(gf2x_mod_mul((uint64_t *)&pad_s[1], (uint64_t *)&pad_ct[1],
                     (uint64_t *)&pad_sk[1]));

  GUARD(gf2x_add(pad_s[0].val.raw, pad_s[0].val.raw, pad_s[1].val.raw, R_SIZE));

  memcpy((uint8_t *)syndrome->qw, pad_s[0].val.raw, R_SIZE);
  dup(syndrome);

  return SUCCESS;
}

_INLINE_ ret_t
recompute_syndrome(OUT syndrome_t *syndrome,
                   IN const ct_t *ct,
                   IN const sk_t *sk,
                   IN const split_e_t *splitted_e)
{
  ct_t tmp_ct = *ct;

  // Adapt the ciphertext
  GUARD(gf2x_add(tmp_ct.val[0].raw, tmp_ct.val[0].raw, splitted_e->val[0].raw,
                 R_SIZE));
  GUARD(gf2x_add(tmp_ct.val[1].raw, tmp_ct.val[1].raw, splitted_e->val[1].raw,
                 R_SIZE));

  // Recompute the syndrome
  GUARD(compute_syndrome(syndrome, &tmp_ct, sk));

  return SUCCESS;
}

_INLINE_ uint8_t
get_threshold(IN const syndrome_t *s)
{
  bike_static_assert(sizeof(*s) >= sizeof(r_t), syndrome_is_large_enough);

  const uint32_t syndrome_weight = r_bits_vector_weight((const r_t *)s->qw);

  // The equations below are defined in BIKE's specification:
  // https://bikesuite.org/files/round2/spec/BIKE-Spec-Round2.2019.03.30.pdf
  // Page 20 Section 2.4.2
  const uint8_t threshold =
      THRESHOLD_COEFF0 + (THRESHOLD_COEFF1 * syndrome_weight);

  DMSG("    Thresold: %d\n", threshold);
  return threshold;
}

// Use half-adder as described in [5].
_INLINE_ void
bit_sliced_adder(OUT upc_t *upc,
                 IN OUT syndrome_t *rotated_syndrome,
                 IN const size_t    num_of_slices)
{
  // From cache-memory perspective this loop should be the outside loop
  for(size_t j = 0; j < num_of_slices; j++)
  {
    for(size_t i = 0; i < R_QW; i++)
    {
      const uint64_t carry = (upc->slice[j].u.qw[i] & rotated_syndrome->qw[i]);
      upc->slice[j].u.qw[i] ^= rotated_syndrome->qw[i];
      rotated_syndrome->qw[i] = carry;
    }
  }
}

_INLINE_ void
bit_slice_full_subtract(OUT upc_t *upc, IN uint8_t val)
{
  // Borrow
  uint64_t br[R_QW] = {0};

  for(size_t j = 0; j < SLICES; j++)
  {

    const uint64_t lsb_mask = 0 - (val & 0x1);
    val >>= 1;

    // Perform a - b with c as the input/output carry
    // br = 0 0 0 0 1 1 1 1
    // a  = 0 0 1 1 0 0 1 1
    // b  = 0 1 0 1 0 1 0 1
    // -------------------
    // o  = 0 1 1 0 0 1 1 1
    // c  = 0 1 0 0 1 1 0 1
    //
    // o  = a^b^c
    //            _     __    _ _   _ _     _
    // br = abc + abc + abc + abc = abc + ((a+b))c

    for(size_t i = 0; i < R_QW; i++)
    {
      const uint64_t a      = upc->slice[j].u.qw[i];
      const uint64_t b      = lsb_mask;
      const uint64_t tmp    = ((~a) & b & (~br[i])) | ((((~a) | b) & br[i]));
      upc->slice[j].u.qw[i] = a ^ b ^ br[i];
      br[i]                 = tmp;
    }
  }
}

// Calculate the Unsatisfied Parity Checks (UPCs) and update the errors
// vector (e) accordingy. In addition, update the black and gray errors vector
// with the relevant values.
_INLINE_ void
find_err1(OUT split_e_t *e,
          OUT split_e_t *black_e,
          OUT split_e_t *gray_e,
          IN const syndrome_t *           syndrome,
          IN const compressed_idx_dv_ar_t wlist,
          IN const uint8_t                threshold)
{
  // This function uses the bit-slice-adder methodology of [5]:
  DEFER_CLEANUP(syndrome_t rotated_syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(upc_t upc, upc_cleanup);

  for(uint32_t i = 0; i < N0; i++)
  {
    // UPC must start from zero at every iteration
    memset(&upc, 0, sizeof(upc));

    // 1) Right-rotate the syndrome for every secret key set bit index
    //    Then slice-add it to the UPC array.
    for(size_t j = 0; j < DV; j++)
    {
      rotate_right(&rotated_syndrome, syndrome, wlist[i].val[j]);
      bit_sliced_adder(&upc, &rotated_syndrome, LOG2_MSB(j + 1));
    }

    // 2) Subtract the threshold from the UPC counters
    bit_slice_full_subtract(&upc, threshold);

    // 3) Update the errors and the black errors vectors.
    //    The last slice of the UPC array holds the MSB of the accumulated values
    //    minus the threshold. Every zero bit indicates a potential error bit.
    //    The errors values are stored in the black array and xored with the
    //    errors Of the previous iteration.
    const r_t *last_slice = &(upc.slice[SLICES - 1].u.r.val);
    for(size_t j = 0; j < R_SIZE; j++)
    {
      const uint8_t sum_msb  = (~last_slice->raw[j]);
      black_e->val[i].raw[j] = sum_msb;
      e->val[i].raw[j] ^= sum_msb;
    }

    // Ensure that the padding bits (upper bits of the last byte) are zero so
    // they will not be included in the multiplication and in the hash function.
    e->val[i].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;

    // 4) Calculate the gray error array by adding "DELTA" to the UPC array.
    //    For that we reuse the rotated_syndrome variable setting it to all "1".
    for(size_t l = 0; l < DELTA; l++)
    {
      memset((uint8_t *)rotated_syndrome.qw, 0xff, R_SIZE);
      bit_sliced_adder(&upc, &rotated_syndrome, SLICES);
    }

    // 5) Update the gray list with the relevant bits that are not
    //    set in the black list.
    for(size_t j = 0; j < R_SIZE; j++)
    {
      const uint8_t sum_msb = (~last_slice->raw[j]);
      gray_e->val[i].raw[j] = (~(black_e->val[i].raw[j])) & sum_msb;
    }
  }
}

// Recalculate the UPCs and update the errors vector (e) according to it
// and to the black/gray vectors.
_INLINE_ void
find_err2(OUT split_e_t *e,
          IN split_e_t *pos_e,
          IN const syndrome_t *           syndrome,
          IN const compressed_idx_dv_ar_t wlist,
          IN const uint8_t                threshold)
{
  DEFER_CLEANUP(syndrome_t rotated_syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(upc_t upc, upc_cleanup);

  for(uint32_t i = 0; i < N0; i++)
  {
    // UPC must start from zero at every iteration
    memset(&upc, 0, sizeof(upc));

    // 1) Right-rotate the syndrome for every secret key set bit index
    //    Then slice-add it to the UPC array.
    for(size_t j = 0; j < DV; j++)
    {
      rotate_right(&rotated_syndrome, syndrome, wlist[i].val[j]);
      bit_sliced_adder(&upc, &rotated_syndrome, LOG2_MSB(j + 1));
    }

    // 2) Subtract the threshold from the UPC counters
    bit_slice_full_subtract(&upc, threshold);

    // 3) Update the errors vector.
    //    The last slice of the UPC array holds the MSB of the accumulated values
    //    minus the threshold. Every zero bit indicates a potential error bit.
    const r_t *last_slice = &(upc.slice[SLICES - 1].u.r.val);
    for(size_t j = 0; j < R_SIZE; j++)
    {
      const uint8_t sum_msb = (~last_slice->raw[j]);
      e->val[i].raw[j] ^= (pos_e->val[i].raw[j] & sum_msb);
    }

    // Ensure that the padding bits (upper bits of the last byte) are zero so
    // they will not be included in the multiplication and in the hash function.
    e->val[i].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
  }
}

ret_t
decode(OUT split_e_t *e,
       IN const syndrome_t *original_s,
       IN const ct_t *ct,
       IN const sk_t *sk)
{
  split_e_t  black_e = {0};
  split_e_t  gray_e  = {0};
  syndrome_t s;

  // Reset (init) the error because it is xored in the find_err funcitons.
  memset(e, 0, sizeof(*e));
  s = *original_s;
  dup(&s);

  for(uint32_t iter = 0; iter < MAX_IT; iter++)
  {
    const uint8_t threshold = get_threshold(&s);

    DMSG("    Iteration: %d\n", iter);
    DMSG("    Weight of e: %lu\n",
         r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
    DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

    find_err1(e, &black_e, &gray_e, &s, sk->wlist, threshold);
    GUARD(recompute_syndrome(&s, ct, sk, e));
#ifdef BGF_DECODER
    if(iter >= 1)
    {
      continue;
    }
#endif
    DMSG("    Weight of e: %lu\n",
         r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
    DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

    find_err2(e, &black_e, &s, sk->wlist, ((DV + 1) / 2) + 1);
    GUARD(recompute_syndrome(&s, ct, sk, e));

    DMSG("    Weight of e: %lu\n",
         r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
    DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

    find_err2(e, &gray_e, &s, sk->wlist, ((DV + 1) / 2) + 1);
    GUARD(recompute_syndrome(&s, ct, sk, e));
  }

  if(r_bits_vector_weight((r_t *)s.qw) > 0)
  {
    BIKE_ERROR(E_DECODING_FAILURE);
  }

  return SUCCESS;
}
