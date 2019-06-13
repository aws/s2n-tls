/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
****************************************************************************/

#include "sampling.h"
#include <string.h>
#include <assert.h>

_INLINE_ status_t get_rand_mod_len(OUT uint32_t *rand_pos,
                                   IN const uint32_t len,
                                   IN OUT aes_ctr_prf_state_t *prf_state)
{
    const uint64_t mask = MASK(bit_scan_reverse(len));
    status_t res = SUCCESS;

    do
    {
        // Generate 128bit of random numbers
        GUARD(aes_ctr_prf((uint8_t*)rand_pos, prf_state, sizeof(*rand_pos)), res, EXIT);

        // Mask only relevant bits
        (*rand_pos) &= mask;

        // Break if a number smaller than len is found
        if ((*rand_pos) < len)
        {
            break;
        }

    } while (1 == 1);

EXIT:
    return res;
}

_INLINE_ status_t make_odd_weight(IN OUT uint8_t *a,
                                  IN const uint32_t len,
                                  IN OUT aes_ctr_prf_state_t *prf_state)
{
    status_t res;
    uint32_t rand_pos = 0;

    if(((count_ones(a, R_SIZE) % 2) == 1))
    {
        // Already odd
        return SUCCESS;
    }

    // Generate random bit and flip it
    GUARD(get_rand_mod_len(&rand_pos, len, prf_state), res, EXIT);

    const uint32_t rand_byte = rand_pos >> 3;
    const uint32_t rand_bit  = rand_pos & 0x7;
        
    a[rand_byte] ^= BIT(rand_bit);

EXIT:
    return SUCCESS;
}

// IN: must_be_odd - 1 true, 0 not
status_t sample_uniform_r_bits(OUT uint8_t *r, 
                               IN const seed_t *seed, 
                               IN const must_be_odd_t must_be_odd)
{
    status_t res = SUCCESS;

    // For the seedexpander
    aes_ctr_prf_state_t prf_state = {0};

    // Both h0 and h1 use the same context
    init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, seed);

    // Generate random data
    GUARD(aes_ctr_prf(r, &prf_state, R_SIZE), res, EXIT);
    
    // Mask upper bits of the MSByte
    r[R_SIZE - 1] &= MASK(R_BITS + 8 - (R_SIZE * 8));

    if(must_be_odd == MUST_BE_ODD)
    {
        GUARD(make_odd_weight(r, R_BITS, &prf_state), res, EXIT);
    }

EXIT:
    finalize_aes_ctr_prf(&prf_state);
    return res;
}

#if defined(CONSTANT_TIME) || defined(VALIDATE_CONSTANT_TIME)
_INLINE_ int is_new2(IN uint32_t wlist[],
                    IN const uint32_t ctr)
{
    for(uint32_t i = 0; i < ctr; i++)
    {
        if(wlist[i] == wlist[ctr])
        {
            return 0;
        }
    }

    return 1;
}
#endif

#ifdef CONSTANT_TIME
_INLINE_ int is_new(IN idx_t wlist[],
                    IN const uint32_t ctr)
{
    for(uint32_t i = 0; i < ctr; i++)
    {
        if(wlist[i].val == wlist[ctr].val)
        {
            return 0;
        }
    }

    return 1;
}

extern status_t __breakpoint__generate_sparse_fake_rep_first_loop(uint64_t**, idx_t**, const uint32_t*, aes_ctr_prf_state_t**, status_t*, uint64_t*, uint32_t (*)[DV], const uint32_t*, uint32_t*, uint32_t*, uint32_t*) __attribute__((noduplicate));
extern status_t __breakpoint__generate_sparse_fake_rep_second_loop(uint64_t**, idx_t**, const uint32_t*, aes_ctr_prf_state_t**, status_t*, uint64_t*, uint32_t (*)[DV], const uint32_t*, uint32_t*, uint32_t*, uint32_t*) __attribute__((noduplicate));
extern status_t __breakpoint__generate_sparse_fake_rep_last_loop(uint64_t**, idx_t**, const uint32_t*, aes_ctr_prf_state_t**, status_t*, uint32_t (*)[DV], const uint32_t*, uint32_t*, uint32_t*, uint32_t*) __attribute__((noduplicate));

// Assumption 1) fake_weight > waight
//            3) paddded_len % 64 = 0!
status_t generate_sparse_fake_rep(OUT uint64_t *a,
                                  OUT idx_t wlist[],
                                  IN  const uint32_t padded_len,
                                  IN OUT aes_ctr_prf_state_t *prf_state)
{
    assert(padded_len % 64 == 0);

    status_t res = SUCCESS;
    uint64_t ctr = 0;
    uint32_t real_wlist[DV] = {0};
	const uint32_t len = R_BITS;
    uint32_t mask = 0;
    uint32_t j, i;

    // Initialize lists
    memset(wlist, 0, sizeof(idx_t)*FAKE_DV);

    // Generate FAKE_DV rand numbers
    do
    {
        __breakpoint__generate_sparse_fake_rep_first_loop(&a, &wlist, &padded_len, &prf_state, &res, &ctr, &real_wlist, &len, &mask, &j, &i);
         GUARD(get_rand_mod_len(&wlist[ctr].val, len, prf_state), res, EXIT);
         ctr += is_new(wlist, ctr);
    } while(ctr < FAKE_DV);

    // Allocate DV real positions
    ctr = 0;
    do
    {
        __breakpoint__generate_sparse_fake_rep_second_loop(&a, &wlist, &padded_len, &prf_state, &res, &ctr, &real_wlist, &len, &mask, &j, &i);
        GUARD(get_rand_mod_len(&real_wlist[ctr], FAKE_DV, prf_state), res, EXIT);
        ctr += is_new2(real_wlist, ctr);
    } while(ctr < DV);

    // Applying the indices in constant time
    for(j = 0; j < FAKE_DV; j++)
    {
        for(i = 0; __breakpoint__generate_sparse_fake_rep_last_loop(&a, &wlist, &padded_len, &prf_state, &res, &real_wlist, &len, &mask, &j, &i), i < DV; i++)
        {
            mask = secure_cmp32(j, real_wlist[i]);
            // Turn on real val mask
            wlist[j].used |= (-1U * mask);
        }
    }

    // Initialize to zero
    memset(a, 0, (len + 7) >> 3);

    // Assign values to "a"
    secure_set_bits(a, wlist, padded_len, FAKE_DV);

EXIT:
    return res;
}

extern status_t __breakpoint__generate_sparse_rep_loop(uint64_t**, idx_t**, const uint32_t*, const uint32_t*, const uint32_t*, aes_ctr_prf_state_t**, status_t*, uint64_t*) __attribute__((noduplicate));

// Assumption 1) paddded_len % 64 = 0!
status_t generate_sparse_rep(OUT uint64_t *a,
                             OUT idx_t wlist[],
                             IN  const uint32_t weight,
                             IN  const uint32_t len,
                             IN  const uint32_t padded_len,
                             IN OUT aes_ctr_prf_state_t *prf_state)
{
    assert(padded_len % 64 == 0);

    status_t res = SUCCESS;
    uint64_t ctr = 0;

    // Generate fake_weight rand numbers
    do
    {
        __breakpoint__generate_sparse_rep_loop(&a, &wlist, &weight, &len, &padded_len, &prf_state, &res, &ctr);
         GUARD(get_rand_mod_len(&wlist[ctr].val, len, prf_state), res, EXIT);

         wlist[ctr].used = -1U;
         ctr += is_new(wlist, ctr);
    } while(ctr < weight);
    
    // Initialize to zero
    memset(a, 0, (len + 7) >> 3);

    // Assign values to "a"
    secure_set_bits(a, wlist, padded_len, weight);

EXIT:
    return res;
}

#else

//////////////////////////////////////
// NON CONSTANT TIME implementation!
//////////////////////////////////////

// Return 1 if set
_INLINE_ int is_bit_set(IN const uint64_t *a,
                        IN const uint32_t pos)
{
    
    const uint32_t qw_pos = pos >> 6;
    const uint32_t bit_pos = pos & 0x3f;

    return ((a[qw_pos] & BIT(bit_pos)) != 0);
}

_INLINE_ void set_bit(IN uint64_t *a,
                      IN const uint32_t pos)
{
    
    const uint32_t qw_pos = pos >> 6;
    const uint32_t bit_pos = pos & 0x3f;

    a[qw_pos] |= BIT(bit_pos);
}

// Assumption fake_weight > waight
status_t generate_sparse_fake_rep(OUT uint64_t *a,
                                  OUT idx_t wlist[],
                                  IN  const uint32_t weight,
                                  IN  const uint32_t fake_weight,
                                  IN  const uint32_t len,
                                  IN  const uint32_t padded_len,
                                  IN OUT aes_ctr_prf_state_t *prf_state)
{
    BIKE_UNUSED(fake_weight);

#ifndef VALIDATE_CONSTANT_TIME
    return generate_sparse_rep(a, wlist, weight, len, padded_len, prf_state);
#else
    // This part of code to be able to compare constant and 
    // non constant time implementations.

    status_t res = SUCCESS;
    uint64_t ctr = 0;
    
    uint32_t real_wlist[weight];
    idx_t inordered_wlist[fake_weight];

    GUARD(generate_sparse_rep(a, inordered_wlist, fake_weight, 
                              len, padded_len, prf_state), res, EXIT);

    // Initialize to zero
    memset(a, 0, (len + 7) >> 3);

    // Allocate weight real positions
    do
    {
        GUARD(get_rand_mod_len(&real_wlist[ctr], fake_weight, prf_state), res, EXIT);

        wlist[ctr].val = inordered_wlist[real_wlist[ctr]].val;
        set_bit(a, wlist[ctr].val);
        
        ctr += is_new2(real_wlist, ctr);
    } while(ctr < weight);

EXIT:
    return res;
#endif
}

// Assumption fake_weight > waight
status_t generate_sparse_rep(OUT uint64_t *a,
                             OUT idx_t wlist[],
                             IN  const uint32_t weight,
                             IN  const uint32_t len,
                             IN  const uint32_t padded_len,
                             IN OUT aes_ctr_prf_state_t *prf_state)
{
    BIKE_UNUSED(padded_len);

    status_t res = SUCCESS;
    uint64_t ctr = 0;

    // Initialize to zero
    memset(a, 0, (len + 7) >> 3);

    do
    {
         GUARD(get_rand_mod_len(&wlist[ctr].val, len, prf_state), res, EXIT);

         if (!is_bit_set(a, wlist[ctr].val))
         {
             set_bit(a, wlist[ctr].val);
             ctr++;
         }
    } while(ctr < weight);

EXIT:
    return res;
}

#endif
