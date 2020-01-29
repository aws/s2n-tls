/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron
 * (drucker.nir@gmail.com, shay.gueron@gmail.com)
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#ifndef __FUNCTIONS_RENAMING_H_INCLUDED__
#define __FUNCTIONS_RENAMING_H_INCLUDED__

#define PASTER(x, y)            x##_##y
#define EVALUATOR(x, y)         PASTER(x, y)
#define RENAME_FUNC_NAME(fname) EVALUATOR(FUNC_PREFIX, fname)

#define keypair RENAME_FUNC_NAME(keypair)
#define decaps  RENAME_FUNC_NAME(decaps)
#define encaps  RENAME_FUNC_NAME(encaps)

#define aes_ctr_prf RENAME_FUNC_NAME(aes_ctr_prf)
#define sample_uniform_r_bits_with_fixed_prf_context \
  RENAME_FUNC_NAME(sample_uniform_r_bits_with_fixed_prf_context)
#define init_aes_ctr_prf_state RENAME_FUNC_NAME(init_aes_ctr_prf_state)
#define generate_sparse_rep    RENAME_FUNC_NAME(generate_sparse_rep)
#define parallel_hash          RENAME_FUNC_NAME(parallel_hash)
#define decode                 RENAME_FUNC_NAME(decode)
#define print_BE               RENAME_FUNC_NAME(print_BE)
#define print_LE               RENAME_FUNC_NAME(print_LE)
#define gf2x_mod_mul           RENAME_FUNC_NAME(gf2x_mod_mul)
#define secure_set_bits        RENAME_FUNC_NAME(secure_set_bits)
#define sha                    RENAME_FUNC_NAME(sha)
#define count_ones             RENAME_FUNC_NAME(count_ones)
#define sha_mb                 RENAME_FUNC_NAME(sha_mb)
#define split_e                RENAME_FUNC_NAME(split_e)
#define compute_syndrome       RENAME_FUNC_NAME(compute_syndrome)
#define bike_errno             RENAME_FUNC_NAME(bike_errno)
#define cyclic_product         RENAME_FUNC_NAME(cyclic_product)
#define ossl_add               RENAME_FUNC_NAME(ossl_add)
#define karatzuba_add1         RENAME_FUNC_NAME(karatzuba_add1)
#define karatzuba_add2         RENAME_FUNC_NAME(karatzuba_add2)
#define gf2x_add               RENAME_FUNC_NAME(gf2x_add)
#define gf2_muladd_4x4         RENAME_FUNC_NAME(gf2_muladd_4x4)
#define red                    RENAME_FUNC_NAME(red)
#define gf2x_mul_1x1           RENAME_FUNC_NAME(gf2x_mul_1x1)
#define rotate_right           RENAME_FUNC_NAME(rotate_right)
#define r_bits_vector_weight   RENAME_FUNC_NAME(r_bits_vector_weight)

#endif //__FUNCTIONS_RENAMING_H_INCLUDED__
