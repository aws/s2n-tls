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

#include "sampling.h"

_INLINE_ uint32_t count_ones(IN const uint8_t* a, 
        IN const uint32_t len)
{
    uint32_t count = 0;

    for(uint32_t i = 0; i < len; i++)
    {
        count += __builtin_popcountll(a[i]);
    }

    return count;
}

status_t get_rand_mod_len(OUT uint32_t* rand_pos,
        IN const uint32_t len,
        IN OUT aes_ctr_prf_state_t* prf_state)
{
    const uint64_t mask = MASK(bit_scan_reverse(len));
    status_t res = SUCCESS;

    do
    {
        //Generate 128bit of random numbers
        res = aes_ctr_prf((uint8_t*)rand_pos, prf_state, sizeof(*rand_pos));  
        CHECK_STATUS(res);

        //Mask only relevant bits
        (*rand_pos) &= mask;

        //Break if a number smaller than len is found.
        if ((*rand_pos) < len)
        {
            break;
        }

    } while (1==1);


    EXIT:
    return res;
}

_INLINE_ status_t make_odd_weight(IN OUT uint8_t* a, 
        IN const uint32_t len,
        IN OUT aes_ctr_prf_state_t* prf_state)
{
    uint32_t rand_pos = 0;
    uint32_t rand_byte, rand_bit;

    if(((count_ones(a, R_SIZE) % 2) == 1))
    {
        //Already odd.
        return SUCCESS;
    }

    //Generate random bit and flip it.
    status_t res = get_rand_mod_len(&rand_pos, len, prf_state);  
    CHECK_STATUS(res);

    rand_byte = rand_pos >> 3;
    rand_bit  = rand_pos & 0x7;

    a[rand_byte] ^= BIT(rand_bit);

    EXIT:
    return SUCCESS;
}

//must_be_odd - 1 true, 0 not
status_t sample_uniform_r_bits(OUT uint8_t* n_rand,
        IN const seed_t* seed,
        IN const must_be_odd_t must_be_odd)
{
    status_t res = SUCCESS;

    //For the seedexpander
    aes_ctr_prf_state_t prf_state = {0};

    //Both h0 and h1 use the same context
    init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, seed);

    //Generate random data.
    res = aes_ctr_prf(n_rand, &prf_state, R_SIZE); 
    CHECK_STATUS(res);

    //Mask upper bits of the MSByte.
    n_rand[R_SIZE-1] &= MASK(R_BITS + 8 - (R_SIZE*8));

    if(must_be_odd == MUST_BE_ODD)
    {
        res = make_odd_weight(n_rand, R_BITS, &prf_state);
        CHECK_STATUS(res);
    }

    EXIT:
    return res;
}

void setZero(uint8_t * r, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++)
        r[i] = 0;
}
int CHECK_BIT(uint8_t * tmp, int position) {
    int index = position/8;
    int pos = position%8;
    return ((tmp[index] >> (pos))  & 0x01);
}
void SET_BIT(uint8_t * tmp, int position) {
    int index = position/8;
    int pos = position%8;
    tmp[index] |= 1UL << (pos);
}

status_t generate_sparse_rep(OUT uint8_t * r,
        IN  const uint32_t weight,
        IN  const uint32_t len,
        IN OUT aes_ctr_prf_state_t *prf_state)
{
    uint32_t rand_pos = 0;
    status_t res = SUCCESS;
    uint64_t ctr      = 0;

    //Ensure r is zero.
    setZero(r, DIVIDE_AND_CEIL(len, 8ULL));

    do
    {
        res = get_rand_mod_len(&rand_pos, len, prf_state);
        CHECK_STATUS(res);


        if (!CHECK_BIT(r, rand_pos))
        {   
            ctr++;	
            //No collision set the bit
            SET_BIT(r, rand_pos);

        }
    } while(ctr != weight);

    EXIT:
    return res;
}

