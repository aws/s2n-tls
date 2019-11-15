/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
*
* The optimizations are based on the description developed in the paper: 
* N. Drucker, S. Gueron, 
* "A toolbox for software optimization of QC-MDPC code-based cryptosystems", 
* ePrint (2017).
* The decoder (in decoder/decoder.c) algorithm is the algorithm included in
* the early submission of CAKE (due to N. Sandrier and R Misoczki).
*
* ***************************************************************************/

#include <string.h>
#include "decode.h"
#include "utilities.h"
#include "gf2x.h"

// Decoding (bit-flipping) parameter
#define MAX_IT 25

////////////////////////////////////////////////////////////////////////////////
// Defined in decode.S file
void compute_counter_of_unsat(OUT uint8_t upc[N_BITS],
                              IN const uint8_t s[R_BITS],
                              IN const compressed_idx_dv_t* inv_h0_compressed,
                              IN const compressed_idx_dv_t* inv_h1_compressed);

void recompute(OUT syndrome_t* s,
               IN const uint32_t num_positions,
               IN const uint32_t positions[R_BITS],
               IN const compressed_idx_dv_t* h_compressed);

void convert_to_redundant_rep(OUT uint8_t* out, 
                              IN const uint8_t * in, 
                              IN const uint64_t len);

////////////////////////////////////////////////////////////////////////////////

typedef ALIGN(16) struct decode_ctx_s
{
    // Count the number of unsatisfied parity-checks:
#ifdef AVX512
    ALIGN(16) uint8_t upc[N_QDQWORDS_BITS];
#else
    ALIGN(16) uint8_t upc[N_DDQWORDS_BITS];
#endif
    
#ifdef CONSTANT_TIME
    e_t black_e;
    e_t gray_e;
#else
    // Black positions are the positions involved in more than "threshold" UPC
    uint32_t black_pos[N0][R_BITS];
    uint32_t num_black_pos[N0];
    
    // Gray positions are the positions involved in more than (threashold - delta) UPC
    uint32_t gray_pos [N0][R_BITS];
    uint32_t num_gray_pos [N0];

    uint32_t unflip_pos[N0][R_BITS];
    uint32_t num_unflip_pos[N0];

    uint32_t gray_pos_to_flip[N0][R_BITS]; 
    uint32_t num_gray_pos_to_flip[N0];
#endif
    int delta;
    uint32_t threshold;
} decode_ctx_t;

void split_e(OUT split_e_t* split_e, IN const e_t* e)
{
    // Copy lower bytes (e0)
    memcpy(PTRV(split_e)[0].raw, e->raw, R_SIZE);

    // Now load second value
    for (uint32_t i = R_SIZE; i < N_SIZE; ++i) {
        PTRV(split_e)
        [1].raw[i - R_SIZE] = ((e->raw[i] << LAST_R_BYTE_TRAIL) |
                               (e->raw[i - 1] >> LAST_R_BYTE_LEAD));
    }

    // Fix corner case
    if (N_SIZE < 2UL * R_SIZE) {
        PTRV(split_e)[1].raw[R_SIZE - 1] = (e->raw[N_SIZE - 1] >> LAST_R_BYTE_LEAD);
    }

    // Fix last value
    PTRV(split_e)[0].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
    PTRV(split_e)[1].raw[R_SIZE - 1] &= LAST_R_BYTE_MASK;
}

// Transpose a row into a column
_INLINE_ void transpose(OUT red_r_t *col, 
                        IN const red_r_t *row)
{
    col->raw[0] = row->raw[0];
    for (uint64_t i = 1; i < R_BITS ; ++i)
    {
        col->raw[i] = row->raw[(R_BITS) - i];
    }
}

void compute_syndrome(OUT syndrome_t* syndrome,
                      IN const ct_t* ct,
                      IN const sk_t* sk)
{
    pad_sk_t pad_sk = {{.u.v.val = PTR(sk).bin[0]}, {.u.v.val = PTR(sk).bin[1]}};

    // gf2x_mod_mul requires the values to be 64bit padded and extra (dbl) space for the results
    dbl_pad_syndrome_t pad_s;

#if BIKE_VER == 1
    pad_ct_t pad_ct = {{.u.v.val = PTRV(ct)[0]}, {.u.v.val = PTRV(ct)[1]}};

    // Compute s = c0*h0 + c1*h1:
    gf2x_mod_mul(pad_s[0].u.qw, pad_ct[0].u.qw, pad_sk[0].u.qw);
    gf2x_mod_mul(pad_s[1].u.qw, pad_ct[1].u.qw, pad_sk[1].u.qw);

    gf2x_add(VAL(pad_s[0]).raw, VAL(pad_s[0]).raw, VAL(pad_s[1]).raw, R_SIZE);

#elif BIKE_VER == 2
    pad_ct_t pad_ct = {.u.v.val = *ct};
    gf2x_mod_mul(pad_s[0].u.qw, pad_ct.u.qw, pad_sk[0].u.qw);

#elif BIKE_VER == 3
    // BIKE3 syndrome: s = c0 + c1*h0
    // NTL is better in this case
    cyclic_product(VAL(pad_s[0]).raw, PTRV(ct)[1].raw, VAL(pad_sk[0]).raw);
    gf2x_add(VAL(pad_s[0]).raw, VAL(pad_s[0]).raw, PTRV(ct)[0].raw, R_SIZE);
#endif

    // Converting to redunandt representation and then transposing the value
    red_r_t s_tmp_bytes = {0};
    convert_to_redundant_rep(s_tmp_bytes.raw, VAL(pad_s[0]).raw, sizeof(s_tmp_bytes));
    transpose(&PTR(syndrome).dup1, &s_tmp_bytes);

    secure_clean(pad_s[0].u.raw, sizeof(pad_s));
    secure_clean(pad_sk[0].u.raw, sizeof(pad_sk));
#if (BIKE_VER != 3)
    secure_clean((uint8_t *) &pad_ct, sizeof(pad_ct));
#endif
}

_INLINE_ uint32_t get_threshold(IN const red_r_t *s)
{
    const uint32_t syndrome_weight = count_ones(s->raw, R_BITS);

#if BIKE_VER==3
  #if   LEVEL==1
    const uint32_t threshold = (13.209 + 0.0060515 * (syndrome_weight));
  #elif LEVEL==3
    const uint32_t threshold = (15.561 + 0.0046692 * (syndrome_weight));
  #elif LEVEL==5
    const uint32_t threshold = (17.061 + 0.0038459 * (syndrome_weight));
  #endif
#else
  #if   LEVEL==1
    const uint32_t threshold = (13.530 + 0.0069721 * (syndrome_weight));
  #elif LEVEL==3
    const uint32_t threshold = (15.932 + 0.0052936 * (syndrome_weight));
  #elif LEVEL==5
    const uint32_t threshold = (17.489 + 0.0043536 * (syndrome_weight));
  #endif
#endif

    DMSG("    Thresold: %d\n", threshold);
    return threshold;
}

#ifdef CONSTANT_TIME
void recompute_syndrome(OUT syndrome_t *syndrome,
                       IN const ct_t *ct,
                       IN const sk_t *sk,
                       IN const e_t *e)
{
     // Split e into e0 and e1. Initialization is done in split_e
    split_e_t splitted_e;
    split_e(&splitted_e, e);

#if BIKE_VER == 1
    ct_t tmp_ct = *ct;

    // Adapt the ciphertext
    gf2x_add(VAL(tmp_ct)[0].raw, VAL(tmp_ct)[0].raw, VAL(splitted_e)[0].raw, R_SIZE);
    gf2x_add(VAL(tmp_ct)[1].raw, VAL(tmp_ct)[1].raw, VAL(splitted_e)[1].raw, R_SIZE);

#elif BIKE_VER == 2
    ct_t tmp_ct;

    // Adapt the ciphertext with e1
    cyclic_product(tmp_ct.raw, VAL(splitted_e)[1].raw, PTR(sk).pk.raw);
    gf2x_add(tmp_ct.raw, tmp_ct.raw, ct->raw, R_SIZE);

    // Adapt the ciphertext with e0
    gf2x_add(tmp_ct.raw, tmp_ct.raw, VAL(splitted_e)[0].raw, R_SIZE);

#elif BIKE_VER == 3
    ct_t tmp_ct;

    // Adapt the ciphertext with e1
    cyclic_product(VAL(tmp_ct)[0].raw, VAL(splitted_e)[1].raw, PTR(sk).pk.u.v.val[0].raw);
    cyclic_product(VAL(tmp_ct)[1].raw, VAL(splitted_e)[1].raw, PTR(sk).pk.u.v.val[1].raw);
    gf2x_add(VAL(tmp_ct)[0].raw, VAL(tmp_ct)[0].raw, PTRV(ct)[0].raw, R_SIZE);
    gf2x_add(VAL(tmp_ct)[1].raw, VAL(tmp_ct)[1].raw, PTRV(ct)[1].raw, R_SIZE);

    // Adapt the ciphertext with e0
    gf2x_add(VAL(tmp_ct)[1].raw, VAL(tmp_ct)[1].raw, VAL(splitted_e)[0].raw, R_SIZE);
#endif

    // Recompute the syndromee
    compute_syndrome(syndrome, &tmp_ct, sk);

    secure_clean(splitted_e.u.raw, sizeof(splitted_e));
}

///////////////////////////////////////////////////////////
// Find_error1/2 are defined in ASM files
//////////////////////////////////////////////////////////
extern void find_error1(IN OUT e_t *e,
                        OUT e_t *black_e,
                        OUT e_t *gray_e,
                        IN const uint8_t *upc,
                        IN const uint32_t black_th,
                        IN const uint32_t gray_th);

extern void find_error2(IN OUT e_t *e,
                        OUT e_t *pos_e,
                        IN const uint8_t *upc,
                        IN const uint32_t threshold);

_INLINE_ void fix_error1(IN OUT syndrome_t *s,
                         IN OUT e_t *e, 
                         IN OUT decode_ctx_t *ctx,
                         IN const sk_t *sk,
                         IN const ct_t *ct)
{
    find_error1(e, &ctx->black_e, &ctx->gray_e, 
                ctx->upc, 
                ctx->threshold, 
                ctx->threshold - ctx->delta + 1);

    recompute_syndrome(s, ct, sk, e);
}

_INLINE_ void fix_black_error(IN OUT syndrome_t *s,
                              IN OUT e_t *e, 
                              IN OUT decode_ctx_t *ctx,
                              IN const sk_t *sk,
                              IN const ct_t *ct)
{
    find_error2(e, &ctx->black_e, ctx->upc, ((DV+1)/2)+1);
    recompute_syndrome(s, ct, sk, e);
}

_INLINE_ void fix_gray_error(IN OUT syndrome_t *s,
                             IN OUT e_t *e, 
                             IN OUT decode_ctx_t *ctx,
                             IN const sk_t *sk,
                             IN const ct_t *ct)
{
    find_error2(e, &ctx->gray_e, ctx->upc, ((DV+1)/2)+1);
    recompute_syndrome(s, ct, sk, e);
}

#else

_INLINE_ void update_e(IN OUT e_t *e, 
                       IN const uint32_t pos, 
                       IN const uint8_t part)
{
    const uint32_t transpose_pos = (pos == 0 ? 0 : (R_BITS - pos)) + (part*R_BITS);
    const uint32_t byte_pos = (transpose_pos >> 3);
    const uint32_t bit_pos = (transpose_pos & 0x7);

    e->raw[byte_pos] ^= BIT(bit_pos);
    EDMSG("      flipping position: %u transpose %u byte_pos %u\n", (uint32_t)(pos + (part*R_BITS)), transpose_pos, byte_pos);
}

_INLINE_ void fix_error1(IN OUT syndrome_t *s,
                         IN OUT e_t *e, 
                         IN OUT decode_ctx_t *ctx,
                         IN const sk_t *sk,
                         IN const ct_t *ct)
{
    BIKE_UNUSED(ct);

    for (uint64_t j = 0; j < N0; j++)
    {
        ctx->num_black_pos[j] = 0;
        ctx->num_gray_pos[j] = 0;

        for (uint64_t i = 0; i < R_BITS; i++)
        {
            if (ctx->upc[i + (j*R_BITS)] >= ctx->threshold)
            {
                ctx->black_pos[j][ctx->num_black_pos[j]++] = i;
                update_e(e, i, j);
            }
            else if(ctx->upc[i + (j*R_BITS)] > ctx->threshold - ctx->delta) 
            {
                ctx->gray_pos[j][ctx->num_gray_pos[j]++] = i;
            }
        }

        recompute(s, ctx->num_black_pos[j], ctx->black_pos[j], &PTR(sk).wlist[j]);
    }
    
}

_INLINE_ void fix_black_error(IN OUT syndrome_t *s,
                              IN OUT e_t *e, 
                              IN OUT decode_ctx_t *ctx,
                              IN const sk_t *sk,
                              IN const ct_t *ct)
{
    BIKE_UNUSED(ct);

    for (uint64_t j = 0; j < N0; j++)
    {
        ctx->num_unflip_pos[j] = 0;
        for (uint64_t i = 0; i < ctx->num_black_pos[j]; i++)
        {
            uint32_t pos = ctx->black_pos[j][i];

            if (ctx->upc[pos + (j * R_BITS)] > (DV + 1) / 2)
            {
                ctx->unflip_pos[j][ctx->num_unflip_pos[j]++] = pos;
                update_e(e, pos, j);
            }
        }
        recompute(s, ctx->num_unflip_pos[j], ctx->unflip_pos[j], &PTR(sk).wlist[j]);
    }
}

_INLINE_ void fix_gray_error(IN OUT syndrome_t *s,
                             IN OUT e_t *e, 
                             IN OUT decode_ctx_t *ctx,
                             IN const sk_t *sk,
                             IN const ct_t *ct)
{
    BIKE_UNUSED(ct);

    for (uint64_t j = 0; j < N0; j++)
    {
        ctx->num_gray_pos_to_flip[j] = 0;
        for (uint64_t i = 0; i < ctx->num_gray_pos[j]; i++)
        {
            uint32_t pos = ctx->gray_pos[j][i];
            if (ctx->upc[pos + (j * R_BITS)] > (DV + 1) / 2)
            {
                ctx->gray_pos_to_flip[j][ctx->num_gray_pos_to_flip[j]++] = pos;
                update_e(e, pos, j);
            }
        }
        recompute(s, ctx->num_gray_pos_to_flip[j], ctx->gray_pos_to_flip[j], &PTR(sk).wlist[j]);
    }
}

#endif

int decode(OUT e_t *e,
           OUT syndrome_t *s,
           IN const ct_t *ct,
           IN const sk_t *sk,
           IN const uint32_t u)
{
    int code_ret = -1;
    syndrome_t original_s;

#ifdef CONSTANT_TIME
    decode_ctx_t ctx = {0};
#else
    // No need to init (performance)
    decode_ctx_t ctx;
    BIKE_UNUSED(ct);
#endif
    
    ALIGN(16) compressed_idx_dv_t inv_h_compressed[N0] = {0};
    for (uint64_t i = 0; i < FAKE_DV; i++)
    {
        inv_h_compressed[0].val[i].val = R_BITS - PTR(sk).wlist[0].val[i].val;
        inv_h_compressed[1].val[i].val = R_BITS - PTR(sk).wlist[1].val[i].val; 

#ifdef CONSTANT_TIME
        inv_h_compressed[0].val[i].used = PTR(sk).wlist[0].val[i].used;
        inv_h_compressed[1].val[i].used = PTR(sk).wlist[1].val[i].used;
#endif
    }

    original_s.u.v.dup1 = PTR(s).dup1;

    for(ctx.delta = MAX_DELTA; 
       (ctx.delta >= 0) && (count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)) > u); 
        ctx.delta--)
    {
        // Reset the error
        memset(e, 0, sizeof(*e));
        
        // Reset the syndrom
        PTR(s).dup1 = original_s.u.v.dup1;
        PTR(s).dup2 = original_s.u.v.dup1;

        for (uint32_t iter = 0; iter < MAX_IT; iter++)
        {
            DMSG("    Iteration: %d\n", iter);
            DMSG("    Weight of e: %lu\n", count_ones(e->raw, sizeof(*e)));
            DMSG("    Weight of syndrome: %lu\n", count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)));

            compute_counter_of_unsat(ctx.upc, s->u.raw, &inv_h_compressed[0], &inv_h_compressed[1]);

            ctx.threshold = get_threshold(&PTR(s).dup1);
            fix_error1(s, e, &ctx, sk, ct);

            // Decoding Step I: check if syndrome is 0 (successful decoding)
            if (count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)) <= u)
            {
                code_ret = 0;
                break;
            }

            DMSG("    Weight of e: %lu\n", count_ones(e->raw, sizeof(*e)));
            DMSG("    Weight of syndrome: %lu\n", count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)));

            // Make sure both duplication are the same!
            memcpy(PTR(s).dup2.raw, PTR(s).dup1.raw, sizeof(PTR(s).dup1));

            // Recompute the UPC
            compute_counter_of_unsat(ctx.upc, s->u.raw, &inv_h_compressed[0], &inv_h_compressed[1]);

            // Decoding Step II: Unflip positions that still have high number of UPC associated
            fix_black_error(s, e, &ctx, sk, ct);
            
            DMSG("    Weight of e: %lu\n", count_ones(e->raw, sizeof(*e)));
            DMSG("    Weight of syndrome: %lu\n", count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)));

            // Decoding Step II: Check if syndrome is 0 (successful decoding)
            if (count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)) <= u)
            {
                code_ret = 0;
                break;
            }

            // Make sure both duplication are the same!
            memcpy(PTR(s).dup2.raw, PTR(s).dup1.raw, sizeof(PTR(s).dup1));

            // Recompute UPC
            compute_counter_of_unsat(ctx.upc, s->u.raw, &inv_h_compressed[0], &inv_h_compressed[1]);
    
            // Decoding Step III: Flip all gray positions associated to high number of UPC 
            fix_gray_error(s, e, &ctx, sk, ct);
        
            // Decoding Step III: Check for successful decoding
            if (count_ones(PTR(s).dup1.raw, sizeof(PTR(s).dup1)) <= u)
            {
                code_ret = 0;
                break;
            }
            
            // Make sure both duplication are the same!
            memcpy(PTR(s).dup2.raw, PTR(s).dup1.raw, sizeof(PTR(s).dup1));
        }
    }
    
    DMSG("    Weight of syndrome: 0\n");

    return code_ret;
}
