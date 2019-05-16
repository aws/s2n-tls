/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#pragma once

#include "sha.h"

// The parallel_hash algorithm uses the technique described in
//  1) S. Gueron, V. Krasnov. Simultaneous Hashing of Multiple Messages.
//     Journal of Information Security 3:319-325 (2012).
//  2) S. Gueron. A j-Lanes Tree Hashing Mode and j-Lanes SHA-256.
//     Journal of Information Security 4:7-11 (2013).
//  See also:
//  3) S. Gueron. Parallelized Hashing via j-Lanes and j-Pointers Tree Modes,
//     with Applications to SHA-256.
//     Journal of Information Security 5:91-113 (2014).
//
// It is designed to convert the serial hashing to a parallelizeable process.
//
// This function assumes that m is of N_BITS length
void parallel_hash(OUT sha_hash_t *out_hash,
                   IN const uint8_t *m,
                   IN const uint32_t la);
