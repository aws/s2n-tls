/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
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

#ifndef _SAMPLE_H_
#define _SAMPLE_H_

#include "openssl_utils.h"
#include "aes_ctr_prf.h"

extern int s2n_openssl_compat_rand(unsigned char *buf, int num);

enum _seeds_purpose
{
    KEYGEN_SEEDS = 0,
    ENCAPS_SEEDS = 1,
    DECAPS_SEEDS = 2
};

typedef enum _seeds_purpose seeds_purpose_t;

_INLINE_ void get_seeds(OUT double_seed_t* seeds, seeds_purpose_t seeds_type __attribute__((unused)) )
{
    s2n_openssl_compat_rand(seeds->u.v.s1.u.raw, sizeof(double_seed_t));
}

typedef enum 
{
    NO_RESTRICTION=0,
    MUST_BE_ODD=1
} must_be_odd_t;

//Return's a BIGNUM with r random bits
//No restrictions exist for the top or bottom bits -
//and the BIGNUM can be smaller than 2^(r-1).
status_t sample_uniform_r_bits(OUT uint8_t* n,
        IN const seed_t* seed,
        IN const must_be_odd_t must_be_odd);

//Generate a random BIGNUM r of length len with a set weight
//Using the random ctx supplied.
status_t generate_sparse_rep(OUT uint8_t* r,
        IN const uint32_t weight,
        IN const uint32_t len,
        IN OUT aes_ctr_prf_state_t *prf_state);

// sample a single number smaller than len.
status_t get_rand_mod_len(OUT uint32_t* rand_pos,
        IN const uint32_t len,
        IN OUT aes_ctr_prf_state_t* prf_state);

#endif //_SAMPLE_H_
