/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
* ***************************************************************************/

#ifndef __TYPES_H_INCLUDED__
#define __TYPES_H_INCLUDED__

#include "bike_defs.h"
#include <stdint.h>

// C99 standard does not support unnamed union and structures.
// This makes the code ugly because we get ugly lines such as
// param.foo1.foo2.foo3.val = param.foo1.foo5.foo6.val
// To avoid this we always use the same structure
// struct { union { struct { some val } v; } u; } name.
// Subsequently, we can make the code more readable by using the three macros below.
// It will be shorter to use P() and V() instead of PTR/VAL, respectively.
// However then it will be harder to "grep" it.
#define PTR(x) x->u.v
#define PTRV(x) (x->u.v.val)
#define VAL(x) (x.u.v.val)

#ifndef __cplusplus

typedef struct uint128_s {
    union {
        uint8_t bytes[16];
        uint32_t dw[4];
        uint64_t qw[2];
    } u;
} uint128_t;

// Make sure no compiler optimizations
#pragma pack(push, 1)

typedef struct r_s {
    uint8_t raw[R_SIZE];
} r_t;

typedef struct e_s {
    uint8_t raw[N_SIZE];
} e_t;

typedef struct generic_param_n_s {
    union {
        struct
        {
            r_t val[N0];
        } v;
        uint8_t raw[N_SIZE];
    } u;
} generic_param_n_t;

#if BIKE_VER == 2
typedef r_t pk_t;
typedef r_t ct_t;
#else
typedef generic_param_n_t pk_t;
typedef generic_param_n_t ct_t;
#endif
typedef generic_param_n_t split_e_t;

typedef struct idx_s {
    uint32_t val;
#ifdef CONSTANT_TIME
    uint32_t used;
#endif
} idx_t;

typedef struct compressed_idx_dv_s {
    idx_t val[FAKE_DV];
} compressed_idx_dv_t;

typedef struct compressed_idx_t_t {
    idx_t val[T1];
} compressed_idx_t_t;

// The secret key holds both representation for avoiding 
// the compression in the decaps stage
typedef struct sk_s
{
    union
    {
        struct 
        {
            r_t bin[N0];
            compressed_idx_dv_t wlist[N0];
#if BIKE_VER>1
            // For caching instead of recalculating during decoding
            pk_t pk;
#endif
        } v;
        uint8_t raw[N0 * (sizeof(r_t) + sizeof(compressed_idx_dv_t))];
    } u;
} sk_t;

// Pad e to the next Block
typedef struct padded_e_s
{
    union
    {
        struct
        {
            e_t val;
            uint8_t pad[N_PADDED_SIZE - N_SIZE];
        } v;
        uint64_t qw[N_PADDED_QW];
        uint8_t  raw[N_PADDED_SIZE];
    } u;
} padded_e_t;

// Pad r to the next Block
typedef struct padded_r_s
{
    union
    {
        struct
        {
            r_t val;
            uint8_t pad[R_PADDED_SIZE - R_SIZE];
        } v;
        uint64_t qw[R_PADDED_QW];
        uint8_t  raw[R_PADDED_SIZE];
    } u;
} padded_r_t;

typedef padded_r_t padded_param_n_t[N0];
typedef padded_param_n_t pad_sk_t;
#if BIKE_VER==2
    typedef padded_r_t pad_pk_t;
    typedef padded_r_t pad_ct_t;
#else
    typedef padded_param_n_t pad_pk_t;
    typedef padded_param_n_t pad_ct_t;
#endif

// Need to allocate twice the room for the results
typedef struct dbl_padded_r_s {
    union {
        struct
        {
            r_t val;
            uint8_t pad[(2 * R_PADDED_SIZE) - R_SIZE];
        } v;
        uint64_t qw[2 * R_PADDED_QW];
        uint8_t raw[2 * R_PADDED_SIZE];
    } u;
} dbl_padded_r_t;

typedef dbl_padded_r_t dbl_padded_param_n_t[N0];
#if BIKE_VER == 2
typedef dbl_padded_r_t dbl_pad_pk_t;
typedef dbl_padded_r_t dbl_pad_ct_t;
#else
typedef dbl_padded_param_n_t dbl_pad_pk_t;
typedef dbl_padded_param_n_t dbl_pad_ct_t;
#endif
typedef dbl_padded_param_n_t dbl_pad_syndrome_t;

typedef struct ss_s {
    uint8_t raw[ELL_K_SIZE];
} ss_t;

// R in redundant representation
typedef struct red_r_s {
    uint8_t raw[R_BITS];
} red_r_t;

// For optimization purposes
//  1- For a faster rotate we duplicate the syndrome (dup1/2)
//  2- We extend it to fit the boundary of DDQW
typedef ALIGN(16) struct syndrome_s {
    union {
        struct {
            red_r_t dup1;
            red_r_t dup2;
#ifdef USE_AVX512F_INSTRUCTIONS
            uint8_t reserved[N_QDQWORDS_BITS - N_BITS];
        } v;
        uint8_t raw[N_QDQWORDS_BITS];
#else
            uint8_t reserved[N_DDQWORDS_BITS - N_BITS];
        } v;
        uint8_t raw[N_DDQWORDS_BITS];
#endif
    } u;
} syndrome_t;

enum _seed_id
{
    G_SEED = 0,
    H_SEED = 1,
    M_SEED = 2,
    E_SEED = 3
};

typedef struct seed_s
{
    union {
        uint8_t  raw[32];
        uint64_t qw[4];
    } u;
} seed_t;

// Both keygen and encaps require double seed
typedef struct double_seed_s
{
    union {
        struct {
            seed_t s1;
            seed_t s2;
        } v;
        uint8_t raw[sizeof(seed_t) * 2ULL];
    } u;
} double_seed_t;

//////////////////////////////
//   Error handling
/////////////////////////////

// This convention will work all over the code
#define ERR(v, return_param, label) {return_param = v; goto label;}
#define GUARD(func, stat, label) {stat = func; if(stat != SUCCESS) {goto label;}}

enum _status
{
    SUCCESS                          = 0,
    E_ERROR_WEIGHT_IS_NOT_T          = 1,
    E_DECODING_FAILURE               = 2,
    E_AES_CTR_PRF_INIT_FAIL          = 3,
    E_AES_OVER_USED                  = 4,
    EXTERNAL_LIB_ERROR_OPENSSL       = 5,
    E_FAIL_TO_GET_SEED               = 6
};

typedef enum _status status_t;

#pragma pack(pop)

#endif //__cplusplus
#endif //__TYPES_H_INCLUDED__

