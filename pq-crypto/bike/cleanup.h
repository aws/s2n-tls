/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#pragma once

#include <string.h>
#include "types.h"
#include "utils/s2n_safety.h"

// len is bytes length of in
_INLINE_ void secure_clean(OUT uint8_t *p, IN const uint32_t len)
{
#ifdef _WIN32
        SecureZeroMemory(p, len);
#else
        typedef void *(*memset_t)(void *, int, size_t);
        static volatile memset_t memset_func = memset;
        memset_func(p, 0, len);
#endif
}

_INLINE_ void r_cleanup(IN OUT r_t *o)                     { secure_clean(o->raw, sizeof(*o)); }
_INLINE_ void e_cleanup(IN OUT e_t *o)                     { secure_clean(o->raw, sizeof(*o)); }
_INLINE_ void padded_r_cleanup(IN OUT padded_r_t *o)       { secure_clean(o->u.raw, sizeof(*o)); }
_INLINE_ void padded_e_cleanup(IN OUT padded_e_t *o)       { secure_clean(o->u.raw, sizeof(*o)); }
_INLINE_ void split_e_cleanup(IN OUT split_e_t *o)         { secure_clean(o->u.raw, sizeof(*o)); }
_INLINE_ void pad_sk_cleanup(IN OUT pad_sk_t *o)           { secure_clean(o[0]->u.raw, sizeof(*o)); }
#if BIKE_VER==2
_INLINE_ void pad_ct_cleanup(IN OUT pad_ct_t *o)           { secure_clean(o->u.raw, sizeof(*o)); }
_INLINE_ void dbl_pad_ct_cleanup(IN OUT dbl_pad_ct_t *o)   { secure_clean(o->u.raw, sizeof(*o)); }
#else
_INLINE_ void pad_ct_cleanup(IN OUT pad_ct_t *o)           { secure_clean(o[0]->u.raw, sizeof(*o)); }
_INLINE_ void dbl_pad_ct_cleanup(IN OUT dbl_pad_ct_t *o)   { secure_clean(o[0]->u.raw, sizeof(*o)); }
#endif
_INLINE_ void double_seed_cleanup(IN OUT double_seed_t *o) { secure_clean(o->u.v.s1.u.raw, sizeof(*o)); }
_INLINE_ void syndrome_cleanup(IN OUT syndrome_t *o)       { secure_clean(o->u.raw, sizeof(*o)); }
_INLINE_ void dbl_pad_syndrome_cleanup(IN OUT dbl_pad_syndrome_t *o)   { secure_clean(o[0]->u.raw, sizeof(*o)); }
_INLINE_ void compressed_idx_dv_ar_cleanup(IN OUT compressed_idx_dv_ar_t *o) 
{
    for(int i=0; i < N0; i++)
    {
        secure_clean((uint8_t*)&o[i], sizeof(*o[0])); 
    }
}
