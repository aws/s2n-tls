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


#ifndef __AES_CTR_REF_H_INCLUDED__
#define __AES_CTR_REF_H_INCLUDED__

#include "types.h"
#include "openssl/aes.h"

#define AES256_KEY_SIZE 32ULL
#define AES256_KEY_BITS (AES256_KEY_SIZE*8)
#define AES256_BLOCK_SIZE 16ULL

#define MAX_AES_INVOKATION (MASK(32))

//////////////////////////////
//        Types
/////////////////////////////

typedef struct aes_ctr_prf_state_s
{
    uint128_t ctr;
    uint128_t buffer;
    AES_KEY   key;
    uint32_t  rem_invokations;
    uint8_t   pos;
} aes_ctr_prf_state_t;

//////////////////////////////
//        Methods
/////////////////////////////

status_t init_aes_ctr_prf_state(OUT aes_ctr_prf_state_t* s,
        IN const uint32_t maxInvokations,
        IN const seed_t* seed);

status_t aes_ctr_prf(OUT uint8_t* a,
        IN OUT aes_ctr_prf_state_t* s,
        IN const uint32_t len);

#endif //__AES_CTR_REF_H_INCLUDED__

