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
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

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
