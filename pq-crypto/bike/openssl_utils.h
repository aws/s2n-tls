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

#ifndef _OSSL_UTILITIES_H_
#define _OSSL_UTILITIES_H_

#include "types.h"

status_t ossl_add(OUT uint8_t res_bin[R_SIZE],
                  IN const uint8_t a_bin[R_SIZE],
                  IN const uint8_t b_bin[R_SIZE]);

// Perform cyclic product by using OpenSSL
status_t cyclic_product(OUT uint8_t res_bin[R_SIZE],
                        IN const uint8_t a_bin[R_SIZE],
                        IN const uint8_t b_bin[R_SIZE]);

status_t ossl_split_polynomial(OUT uint8_t e0_bin[R_SIZE],
                               OUT uint8_t e1_bin[R_SIZE],
                               IN const uint8_t e_bin[N_SIZE]);

// Perform modular inverse with OpenSSL
status_t mod_inv(OUT uint8_t res_bin[R_SIZE],
                 IN const uint8_t a_bin[R_SIZE]);

#endif // _OSSL_UTILITIES_H_
