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

#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#include "types.h"

//Printing values in Little Endian
void print_LE(IN const uint64_t *in, IN const uint32_t bits_num);

//Printing values in Big Endian
void print_BE(IN const uint64_t *in, IN const uint32_t bits_num);

//Printing number is required only in verbose level 2 or above.
#if VERBOSE==2
#ifdef PRINT_IN_BE
//Print in Big Endian
#define print(in, bits_num) print_BE(in, bits_num)
#else
//Print in Little Endian
#define print(in, bits_num) print_LE(in, bits_num)
#endif
#else
//No prints at all
#define print(in, bits_num)
#endif

//Comparing value in a constant time manner.
_INLINE_ uint32_t safe_cmp(IN const uint8_t* a,
        IN const uint8_t* b,
        IN const uint32_t size)
{
    volatile uint8_t res = 0;

    for(uint32_t i=0; i < size; ++i)
    {
        res |= (a[i] ^ b[i]);
    }

    return (res == 0);
}

//BSR returns ceil(log2(val))
_INLINE_ uint8_t bit_scan_reverse(uint64_t val)
{
    //index is always smaller than 64.
    uint8_t index = 0;

    while(val != 0)
    {
        val >>= 1;
        index++;
    }

    return index;
}

#endif //_UTILITIES_H_
