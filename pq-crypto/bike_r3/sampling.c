/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include <assert.h>

#include "sampling.h"
#include "sampling_internal.h"

// SIMD implementation of is_new function requires the size of wlist
// to be a multiple of the number of DWORDS in a SIMD register (REG_DWORDS).
// The function is used both for generating DV and T1 random numbers so we define
// two separate macros.
#define AVX512_REG_DWORDS (16)
#define WLIST_SIZE_ADJUSTED_D \
  (AVX512_REG_DWORDS * DIVIDE_AND_CEIL(DV, AVX512_REG_DWORDS))
#define WLIST_SIZE_ADJUSTED_T \
  (AVX512_REG_DWORDS * DIVIDE_AND_CEIL(T1, AVX512_REG_DWORDS))

// BSR returns ceil(log2(val))
_INLINE_ uint8_t bit_scan_reverse_vartime(IN uint64_t val)
{
  // index is always smaller than 64
  uint8_t index = 0;

  while(val != 0) {
    val >>= 1;
    index++;
  }

  return index;
}

_INLINE_ ret_t get_rand_mod_len(OUT uint32_t *    rand_pos,
                                IN const uint32_t len,
                                IN OUT aes_ctr_prf_state_t *prf_state)
{
  const uint64_t mask = MASK(bit_scan_reverse_vartime(len));

  do {
    // Generate a 32 bits (pseudo) random value.
    // This can be optimized to take only 16 bits.
    POSIX_GUARD(aes_ctr_prf((uint8_t *)rand_pos, prf_state, sizeof(*rand_pos)));

    // Mask relevant bits only
    (*rand_pos) &= mask;

    // Break if a number that is smaller than len is found
    if((*rand_pos) < len) {
      break;
    }

  } while(1 == 1);

  return SUCCESS;
}

_INLINE_ void make_odd_weight(IN OUT r_t *r)
{
  if(((r_bits_vector_weight(r) % 2) == 1)) {
    // Already odd
    return;
  }

  r->raw[0] ^= 1;
}

// Returns an array of r pseudorandom bits.
// No restrictions exist for the top or bottom bits.
// If the generation requires an odd number, then set must_be_odd=1.
// The function uses the provided prf context.
ret_t sample_uniform_r_bits_with_fixed_prf_context(
  OUT r_t *r,
  IN OUT aes_ctr_prf_state_t *prf_state,
  IN const must_be_odd_t      must_be_odd)
{
  // Generate random data
  POSIX_GUARD(aes_ctr_prf(r->raw, prf_state, R_BYTES));

  // Mask upper bits of the MSByte
  r->raw[R_BYTES - 1] &= MASK(R_BITS + 8 - (R_BYTES * 8));

  if(must_be_odd == MUST_BE_ODD) {
    make_odd_weight(r);
  }

  return SUCCESS;
}

ret_t generate_indices_mod_z(OUT idx_t *     out,
                             IN const size_t num_indices,
                             IN const size_t z,
                             IN OUT aes_ctr_prf_state_t *prf_state,
                             IN const sampling_ctx *ctx)
{
  size_t ctr = 0;

  // Generate num_indices unique (pseudo) random numbers modulo z
  do {
    POSIX_GUARD(get_rand_mod_len(&out[ctr], z, prf_state));
    ctr += ctx->is_new(out, ctr);
  } while(ctr < num_indices);

  return SUCCESS;
}

// Returns an array of r pseudorandom bits.
// No restrictions exist for the top or bottom bits.
// If the generation requires an odd number, then set must_be_odd = MUST_BE_ODD
ret_t sample_uniform_r_bits(OUT r_t *r,
                            IN const seed_t *      seed,
                            IN const must_be_odd_t must_be_odd)
{
  // For the seedexpander
  DEFER_CLEANUP(aes_ctr_prf_state_t prf_state = {0}, aes_ctr_prf_state_cleanup);

  POSIX_GUARD(init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, seed));

  POSIX_GUARD(sample_uniform_r_bits_with_fixed_prf_context(r, &prf_state, must_be_odd));

  return SUCCESS;
}

ret_t generate_sparse_rep(OUT pad_r_t *r,
                          OUT idx_t *wlist,
                          IN OUT aes_ctr_prf_state_t *prf_state)
{

  // Initialize the sampling context
  sampling_ctx ctx;
  sampling_ctx_init(&ctx);

  idx_t wlist_temp[WLIST_SIZE_ADJUSTED_D] = {0};

  POSIX_GUARD(generate_indices_mod_z(wlist_temp, DV, R_BITS, prf_state, &ctx));

  bike_memcpy(wlist, wlist_temp, DV * sizeof(idx_t));
  ctx.secure_set_bits(r, 0, wlist, DV);

  return SUCCESS;
}

ret_t generate_error_vector(OUT pad_e_t *e, IN const seed_t *seed)
{
  DEFER_CLEANUP(aes_ctr_prf_state_t prf_state = {0}, aes_ctr_prf_state_cleanup);

  POSIX_GUARD(init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, seed));

  // Initialize the sampling context
  sampling_ctx ctx;
  sampling_ctx_init(&ctx);

  idx_t wlist[WLIST_SIZE_ADJUSTED_T] = {0};
  POSIX_GUARD(generate_indices_mod_z(wlist, T1, N_BITS, &prf_state, &ctx));

  // (e0, e1) hold bits 0..R_BITS-1 and R_BITS..2*R_BITS-1 of the error, resp.
  ctx.secure_set_bits(&e->val[0], 0, wlist, T1);
  ctx.secure_set_bits(&e->val[1], R_BITS, wlist, T1);

  // Clean the padding of the elements
  PE0_RAW(e)[R_BYTES - 1] &= LAST_R_BYTE_MASK;
  PE1_RAW(e)[R_BYTES - 1] &= LAST_R_BYTE_MASK;
  bike_memset(&PE0_RAW(e)[R_BYTES], 0, R_PADDED_BYTES - R_BYTES);
  bike_memset(&PE1_RAW(e)[R_BYTES], 0, R_PADDED_BYTES - R_BYTES);

  return SUCCESS;
}
