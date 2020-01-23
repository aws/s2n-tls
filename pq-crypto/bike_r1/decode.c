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
 *
 * The optimizations are based on the description developed in the paper:
 * N. Drucker, S. Gueron,
 * "A toolbox for software optimization of QC-MDPC code-based cryptosystems",
 * ePrint (2017).
 * The decoder (in decoder/decoder.c) algorithm is the algorithm included in
 * the early submission of CAKE (due to N. Sandrier and R Misoczki).
 *
 ****************************************************************************/

#include "decode.h"
#include "gf2x.h"
#include "utilities.h"
#include <string.h>

// Decoding (bit-flipping) parameter
#define MAX_IT 4

////////////////////////////////////////////////////////////////////////////////
// Defined in decode.S file
EXTERNC void
compute_counter_of_unsat(OUT uint8_t      upc[N_BITS],
                         IN const uint8_t s[N_BITS],
                         IN const compressed_idx_dv_t *inv_h0_compressed,
                         IN const compressed_idx_dv_t *inv_h1_compressed);

EXTERNC void
recompute(OUT syndrome_t *  s,
          IN const uint32_t num_positions,
          IN const uint32_t positions[R_BITS],
          IN const compressed_idx_dv_t *h_compressed);

EXTERNC void
convert_to_redundant_rep(OUT uint8_t *out,
                         IN const uint8_t *in,
                         IN const uint64_t len);

////////////////////////////////////////////////////////////////////////////////

typedef ALIGN(16) struct decode_ctx_s
{
  // Count the number of unsatisfied parity-checks:
  ALIGN(16) uint8_t upc[N_DDQWORDS_BITS];

  e_t      black_e;
  e_t      gray_e;
  int      delta;
  uint32_t threshold;
} decode_ctx_t;

void
split_e(OUT split_e_t *split_e_, IN const e_t *e)
{
  // Copy lower bytes (e0)
  memcpy(PTRV(split_e_)[0].raw, e->raw, R_SIZE);

  // Now load second value
  for(uint32_t i = R_SIZE; i < N_SIZE; ++i)
  {
    PTRV(split_e_)
    [1].raw[i - R_SIZE] =
        ((e->raw[i] << LAST_R_BYTE_TRAIL) | (e->raw[i - 1] >> LAST_R_BYTE_LEAD));
  }

  // Fix corner case
  if(N_SIZE < (2ULL * R_SIZE))
  {
    PTRV(split_e_)[1].raw[R_SIZE - 1] = (e->raw[N_SIZE - 1] >> LAST_R_BYTE_LEAD);
  }

  // Fix last value
  PTRV(split_e_)[0].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
  PTRV(split_e_)[1].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
}

// Transpose a row into a column
_INLINE_ void
transpose(OUT red_r_t *col, IN const red_r_t *row)
{
  col->raw[0] = row->raw[0];
  for(uint64_t i = 1; i < R_BITS; ++i)
  {
    col->raw[i] = row->raw[(R_BITS)-i];
  }
}

ret_t
compute_syndrome(OUT syndrome_t *syndrome, IN const ct_t *ct, IN const sk_t *sk)
{
  // gf2x_mod_mul requires the values to be 64bit padded and extra (dbl) space for
  // the results
  DEFER_CLEANUP(dbl_pad_syndrome_t pad_s, dbl_pad_syndrome_cleanup);
  DEFER_CLEANUP(pad_ct_t pad_ct = {0}, pad_ct_cleanup);
  DEFER_CLEANUP(pad_sk_t pad_sk = {0}, pad_sk_cleanup);
  VAL(pad_sk[0]) = PTR(sk).bin[0];
  VAL(pad_sk[1]) = PTR(sk).bin[1];
  VAL(pad_ct[0]) = PTRV(ct)[0];
  VAL(pad_ct[1]) = PTRV(ct)[1];

  // Compute s = c0*h0 + c1*h1:
  GUARD(gf2x_mod_mul(pad_s[0].u.qw, pad_ct[0].u.qw, pad_sk[0].u.qw));
  GUARD(gf2x_mod_mul(pad_s[1].u.qw, pad_ct[1].u.qw, pad_sk[1].u.qw));

  GUARD(
      gf2x_add(VAL(pad_s[0]).raw, VAL(pad_s[0]).raw, VAL(pad_s[1]).raw, R_SIZE));

  // Converting to redunandt representation and then transposing the value
  red_r_t s_tmp_bytes = {0};
  convert_to_redundant_rep(s_tmp_bytes.raw, VAL(pad_s[0]).raw,
                           sizeof(s_tmp_bytes));
  transpose(&PTR(syndrome).dup1, &s_tmp_bytes);

  PTR(syndrome).dup2 = PTR(syndrome).dup1;

  return SUCCESS;
}

_INLINE_ uint32_t
get_threshold(IN const red_r_t *s)
{
  const uint32_t syndrome_weight = count_ones(s->raw, R_BITS);

  // The equations below are defined in BIKE's specification:
  // https://bikesuite.org/files/round2/spec/BIKE-Spec-Round2.2019.03.30.pdf
  // Page 20 Section 2.4.2
  const uint32_t threshold = (13.530 + 0.0069721 * (syndrome_weight));

  DMSG("    Thresold: %d\n", threshold);
  return threshold;
}

ret_t
recompute_syndrome(OUT syndrome_t *syndrome,
                   IN const ct_t *ct,
                   IN const sk_t *sk,
                   IN const e_t *e)
{
  // Split e into e0 and e1. Initialization is done in split_e
  DEFER_CLEANUP(split_e_t splitted_e, split_e_cleanup);
  split_e(&splitted_e, e);

  ct_t tmp_ct = *ct;

  // Adapt the ciphertext
  GUARD(gf2x_add(VAL(tmp_ct)[0].raw, VAL(tmp_ct)[0].raw, VAL(splitted_e)[0].raw,
                 R_SIZE));
  GUARD(gf2x_add(VAL(tmp_ct)[1].raw, VAL(tmp_ct)[1].raw, VAL(splitted_e)[1].raw,
                 R_SIZE));

  // Recompute the syndrome
  GUARD(compute_syndrome(syndrome, &tmp_ct, sk));

  return SUCCESS;
}

///////////////////////////////////////////////////////////
// Find_error1/2 are defined in ASM files
//////////////////////////////////////////////////////////
EXTERNC void
find_error1(IN OUT e_t *e,
            OUT e_t *black_e,
            OUT e_t *gray_e,
            IN const uint8_t *upc,
            IN const uint32_t black_th,
            IN const uint32_t gray_th);

EXTERNC void
find_error2(IN OUT e_t *e,
            OUT e_t *pos_e,
            IN const uint8_t *upc,
            IN const uint32_t threshold);

_INLINE_ ret_t
fix_error1(IN OUT syndrome_t *s,
           IN OUT e_t *e,
           IN OUT decode_ctx_t *ctx,
           IN const sk_t *sk,
           IN const ct_t *ct)
{
  find_error1(e, &ctx->black_e, &ctx->gray_e, ctx->upc, ctx->threshold,
              ctx->threshold - ctx->delta + 1);

  GUARD(recompute_syndrome(s, ct, sk, e));

  return SUCCESS;
}

_INLINE_ ret_t
fix_black_error(IN OUT syndrome_t *s,
                IN OUT e_t *e,
                IN OUT decode_ctx_t *ctx,
                IN const sk_t *sk,
                IN const ct_t *ct)
{
  find_error2(e, &ctx->black_e, ctx->upc, ((DV + 1) / 2) + 1);
  GUARD(recompute_syndrome(s, ct, sk, e));

  return SUCCESS;
}

_INLINE_ ret_t
fix_gray_error(IN OUT syndrome_t *s,
               IN OUT e_t *e,
               IN OUT decode_ctx_t *ctx,
               IN const sk_t *sk,
               IN const ct_t *ct)
{
  find_error2(e, &ctx->gray_e, ctx->upc, ((DV + 1) / 2) + 1);
  GUARD(recompute_syndrome(s, ct, sk, e));

  return SUCCESS;
}

ret_t
decode(OUT e_t *e,
       IN const syndrome_t *original_s,
       IN const ct_t *ct,
       IN const sk_t *   sk,
       IN const uint32_t u)
{
  syndrome_t  _s;
  syndrome_t *s = &_s;

  decode_ctx_t ctx = {0};

  ALIGN(16)
  DEFER_CLEANUP(compressed_idx_dv_ar_t inv_h_compressed = {0},
                compressed_idx_dv_ar_cleanup);

  for(uint64_t i = 0; i < FAKE_DV; i++)
  {
    if((PTR(sk).wlist[0].val[i].val > R_BITS) ||
       (PTR(sk).wlist[1].val[i].val > R_BITS))
    {
      BIKE_ERROR(E_DECODING_FAILURE);
    }

    inv_h_compressed[0].val[i].val  = R_BITS - PTR(sk).wlist[0].val[i].val;
    inv_h_compressed[1].val[i].val  = R_BITS - PTR(sk).wlist[1].val[i].val;
    inv_h_compressed[0].val[i].used = PTR(sk).wlist[0].val[i].used;
    inv_h_compressed[1].val[i].used = PTR(sk).wlist[1].val[i].used;
  }

  PTR(s).dup1 = PTR(original_s).dup1;
  ctx.delta   = MAX_DELTA;

  // Reset the error
  memset(e, 0, sizeof(*e));

  // Reset the syndrome
  PTR(s).dup1 = PTR(original_s).dup1;
  PTR(s).dup2 = PTR(original_s).dup1;

  for(uint32_t iter = 0; iter < MAX_IT; iter++)
  {
    DMSG("    Iteration: %d\n", iter);
    DMSG("    Weight of e: %lu\n", count_ones(e->raw, sizeof(*e)));
    DMSG("    Weight of syndrome: %lu\n",
         count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)));

    compute_counter_of_unsat(ctx.upc, s->u.raw, &inv_h_compressed[0],
                             &inv_h_compressed[1]);

    ctx.threshold = get_threshold(&PTR(s).dup1);
    GUARD(fix_error1(s, e, &ctx, sk, ct));

    DMSG("    Weight of e: %lu\n", count_ones(e->raw, sizeof(*e)));
    DMSG("    Weight of syndrome: %lu\n",
         count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)));

    // Recompute the UPC
    compute_counter_of_unsat(ctx.upc, s->u.raw, &inv_h_compressed[0],
                             &inv_h_compressed[1]);

    // Decoding Step II: Unflip positions that still have high number of UPC
    // associated
    GUARD(fix_black_error(s, e, &ctx, sk, ct));

    DMSG("    Weight of e: %lu\n", count_ones(e->raw, sizeof(*e)));
    DMSG("    Weight of syndrome: %lu\n",
         count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)));

    // Recompute UPC
    compute_counter_of_unsat(ctx.upc, s->u.raw, &inv_h_compressed[0],
                             &inv_h_compressed[1]);

    // Decoding Step III: Flip all gray positions associated to high number of UPC
    GUARD(fix_gray_error(s, e, &ctx, sk, ct));
  }

  if(count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)) > u)
  {
    BIKE_ERROR(E_DECODING_FAILURE);
  }

  return SUCCESS;
}
