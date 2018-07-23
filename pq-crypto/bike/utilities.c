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

#include "utilities.h"
#include "stdio.h"
#include "openssl_utils.h"

#define BITS_IN_QW 64ULL
#define BITS_IN_BYTE 8ULL

#ifndef bswap_64
#define bswap_64(x) __builtin_bswap64(x)
#endif

//Print a new line only if we prints in qw blocks.
_INLINE_ void print_newline(IN const uint64_t qw_pos)
{
#ifndef NO_NEWLINE
    if((qw_pos % 4) == 3)
    {
        printf("\n    ");
    }
#endif
}

//Prints a QW in LE/BE in win/linux format.
_INLINE_ void print_uint64(IN const uint64_t val)
{
    //If printing in BE is required swap the order of bytes.
#ifdef PRINT_IN_BE
    uint64_t tmp = bswap_64(val);
#else
    uint64_t tmp = val;
#endif

#ifdef WIN32
    printf("%.16I64x", tmp);
#elif __APPLE__
    printf("%.16llx",  tmp);
#else
    printf("%.16lx",  tmp);
#endif

#ifndef NO_SPACE
    printf(" ");
#endif
}

//Last block requires a special handling as we should zero mask all the bits above the desired number.
//endien - 0 - BE, 1 - LE
//Return 1 if last block was printed else 0.
_INLINE_ uint8_t print_last_block(IN const uint8_t* last_bytes,
        IN const uint32_t bits_num,
        IN const uint32_t endien)
{
    //Floor of bits/64 the reminder is in the next QW.
    const uint32_t qw_num = bits_num/BITS_IN_QW;

    //How many bits to pad with zero.
    const uint32_t rem_bits = bits_num - (BITS_IN_QW * qw_num);

    //We read byte byte and not the whole QW to avoid reading bad memory address.
    const uint32_t bytes_num = (rem_bits % 8 == 0) ? rem_bits/BITS_IN_BYTE : 1 + rem_bits/BITS_IN_BYTE;

    int i;

    if(rem_bits == 0)
    {
        return 0;
    }

    //Mask unneeded bits
    const uint8_t last_byte = (rem_bits % 8 == 0) ? last_bytes[bytes_num - 1] :
            last_bytes[bytes_num - 1] & MASK(rem_bits % 8);
    //BE
    if(endien == 0)
    {
        for(i = 0; (uint32_t)i < (bytes_num - 1); i++)
        {
            printf("%.2x", last_bytes[i]);
        }

        printf("%.2x", last_byte);

        for(i++; (uint32_t)i < sizeof(uint64_t); i++)
        {
            printf("__");
        }
    }
    else
    {
        for(i = sizeof(uint64_t) - 1; (uint32_t)i >= bytes_num ; i--)
        {
            printf("__");
        }

        printf("%.2x", last_byte);

        for(i--; i >= 0; i--)
        {
            printf("%.2x", last_bytes[i]);
        }
    }

#ifndef NO_SPACE
    printf(" ");
#endif

    return 1;
}

void print_LE(IN const uint64_t *in, IN const uint32_t bits_num)
{
    const uint32_t qw_num = bits_num/BITS_IN_QW;

    //Print the MSB QW
    uint32_t qw_pos = print_last_block((uint8_t*)&in[qw_num], bits_num, 1);

    //Print each 8 bytes separated by space (if required)
    for(int i = ((int)qw_num)-1; i >= 0; i--, qw_pos++)
    {
        print_uint64(in[i]);
        print_newline(qw_pos);
    }

    printf("\n");
}

void print_BE(IN const uint64_t *in, IN const uint32_t bits_num)
{
    const uint32_t qw_num = bits_num/BITS_IN_QW;

    //Print each 16 numbers separately.
    for(uint32_t i = 0; i < qw_num ; ++i)
    {
        print_uint64(in[i]);
        print_newline(i);
    }

    //Print the MSB QW
    print_last_block((uint8_t*)&in[qw_num], bits_num, 0);

    printf("\n");
}

