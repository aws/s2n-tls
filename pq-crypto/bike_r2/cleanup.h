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

#pragma once
#include "types.h"
#include "utils/s2n_safety.h"

_INLINE_ void
secure_clean(OUT uint8_t *p, IN const uint32_t len)
{
#ifdef _WIN32
  SecureZeroMemory(p, len);
#else
  typedef void *(*memset_t)(void *, int, size_t);
  static volatile memset_t memset_func = memset;
  memset_func(p, 0, len);
#endif
}

_INLINE_ void
r_cleanup(IN OUT r_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
e_cleanup(IN OUT e_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
padded_r_cleanup(IN OUT padded_r_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
padded_e_cleanup(IN OUT padded_e_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
split_e_cleanup(IN OUT split_e_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
pad_sk_cleanup(IN OUT pad_sk_t *o)
{
  secure_clean((uint8_t *)o[0], sizeof(*o));
}

_INLINE_ void
pad_ct_cleanup(IN OUT pad_ct_t *o)
{
  secure_clean((uint8_t *)o[0], sizeof(*o));
}

_INLINE_ void
dbl_pad_ct_cleanup(IN OUT dbl_pad_ct_t *o)
{
  secure_clean((uint8_t *)o[0], sizeof(*o));
}

_INLINE_ void
seed_cleanup(IN OUT seed_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
syndrome_cleanup(IN OUT syndrome_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
dbl_pad_syndrome_cleanup(IN OUT dbl_pad_syndrome_t *o)
{
  secure_clean((uint8_t *)o[0], sizeof(*o));
}

_INLINE_ void
compressed_idx_t_cleanup(IN OUT compressed_idx_t_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
compressed_idx_dv_ar_cleanup(IN OUT compressed_idx_dv_ar_t *o)
{
  for(int i = 0; i < N0; i++)
  {
    secure_clean((uint8_t *)&(*o)[i], sizeof((*o)[0]));
  }
}

_INLINE_ void
generic_param_n_cleanup(IN OUT generic_param_n_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}

_INLINE_ void
seeds_cleanup(IN OUT seeds_t *o)
{
  for(int i = 0; i < NUM_OF_SEEDS; i++)
  {
    seed_cleanup(&(o->seed[i]));
  }
}

_INLINE_ void
upc_cleanup(IN OUT upc_t *o)
{
  secure_clean((uint8_t *)o, sizeof(*o));
}
