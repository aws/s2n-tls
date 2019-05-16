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

#include "types.h"

ret_t ossl_add(OUT uint8_t res_bin[R_SIZE],
               IN const uint8_t a_bin[R_SIZE],
               IN const uint8_t b_bin[R_SIZE]);

// Perform cyclic product by using OpenSSL
ret_t cyclic_product(OUT uint8_t res_bin[R_SIZE],
                     IN const uint8_t a_bin[R_SIZE],
                     IN const uint8_t b_bin[R_SIZE]);

ret_t ossl_split_polynomial(OUT uint8_t e0_bin[R_SIZE],
                            OUT uint8_t e1_bin[R_SIZE],
                            IN const uint8_t e_bin[N_SIZE]);

// Perform modular inverse with OpenSSL
ret_t mod_inv(OUT uint8_t res_bin[R_SIZE],
              IN const uint8_t a_bin[R_SIZE]);
