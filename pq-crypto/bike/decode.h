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

#pragma once

#include "types.h"

void split_e(OUT split_e_t* split_e, IN const e_t* e);

void compute_syndrome(OUT syndrome_t* syndrome,
                      IN const ct_t* ct,
                      IN const sk_t* sk);

//e should be zeroed before calling the decoder.
int decode(OUT e_t* e,
           IN const syndrome_t* s,
           IN const ct_t* ct,
           IN const sk_t* sk,
           IN const uint32_t u);
