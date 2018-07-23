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

#include "types.h"

//////////////////////////////////////////
//      Conversion functions.
/////////////////////////////////////////

void convert2compact(OUT uint32_t out[DV], IN const uint8_t in[R_BITS])
{
    uint32_t idx=0;

    for (uint32_t i = 0; i < R_SIZE; i++)
    {
        for (uint32_t j = 0; j < 8ULL; j++)
        {
            if ((i*8 + j) == R_BITS)
            {
                break;
            }

            if ((in[i] >> j) & 1)
            {
                out[idx++] = i*8+j;
            }
        }
    }
}

// convert a sequence of uint8_t elements which fully uses all 8-bits of an uint8_t element to
// a sequence of uint8_t which uses just a single bit per byte (either 0 or 1).
int convertByteToBinary(uint8_t* out, uint8_t * in, uint32_t length)
{
    uint32_t paddingLen = length % 8;
    uint32_t numBytes = (paddingLen == 0) ? (length / 8) : (1 + (length/8));

    for (uint32_t i = 0; i < numBytes; i++)
    {
        for (uint32_t j = 0; j < 8ULL; j++)
        {
            if ((i*8 + j) == length)
            {
                break;
            }

            if ((in[i] >> j) & 1)
            {
                out[i*8+j] = 1;
            }
        }
    }
    return 0;
}

// convert a sequence of uint8_t elements which uses just a single bit per byte (either 0 or 1) to
// a sequence of uint8_t which fully uses all 8-bits of an uint8_t element.
int convertBinaryToByte(uint8_t * out, const uint8_t* in, uint32_t length)
{
    uint32_t paddingLen = length % 8;
    uint32_t numBytes = (paddingLen == 0) ? (length / 8) : (1 + (length/8));

    for (uint32_t i = 0; i < numBytes; i++)
    {
        for (uint32_t j = 0; j < 8; j++)
        {
            if ((i*8 + j) == length)
            {
                break;
            }

            if (in[i*8 + j])
            {
                out[i] |= (uint8_t)(1 << j);
            }
        }
    }
    return 0;
}
