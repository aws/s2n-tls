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

#include "decode.h"
#include "utilities.h"

// Convert a sequence of uint8_t elements which fully uses all 8-bits of 
// an uint8_t element to a sequence of uint8_t which uses just a single 
// bit per byte (either 0 or 1).
void convert_to_redundant_rep(OUT uint8_t* out, 
                              IN const uint8_t * in, 
                              IN const uint64_t len)
{
    for(uint32_t i = 0; i <= (len/8); i++)
    {
        uint8_t tmp = in[i];
        for(uint8_t j = 0; j < 8; j++)
        {
            out[8*i+j] |= (tmp & 0x1);
            tmp >>= 1;
        }
    }
}

uint64_t count_ones(IN const uint8_t* in, IN const uint32_t len)
{
    uint64_t acc = 0;
    for(uint32_t i = 0; i < len; i++)
    {
        acc += __builtin_popcount(in[i]);
    }
    
    return acc;
}
