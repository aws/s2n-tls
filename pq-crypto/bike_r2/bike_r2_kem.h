/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

#define IN
#define OUT

////////////////////////////////////////////////////////////////
// The three APIs below (keypair, enc, dec) are defined by NIST:
////////////////////////////////////////////////////////////////
// Keygenerate - pk is the public key
//               sk is the private key
// Return 0 for success and !0 for failures. See types.h for failure codes
int
BIKE1_L1_R2_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

// Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
// Return 0 for success and !0 for failures. See types.h for failure codes
int
BIKE1_L1_R2_crypto_kem_enc(OUT unsigned char *     ct,
                           OUT unsigned char *     ss,
                           IN const unsigned char *pk);

// Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
// Return 0 for success and !0 for failures. See types.h for failure codes
int
BIKE1_L1_R2_crypto_kem_dec(OUT unsigned char *     ss,
                           IN const unsigned char *ct,
                           IN const unsigned char *sk);

#define BIKE1_L1_R2_SECRET_KEY_BYTES    6460
#define BIKE1_L1_R2_PUBLIC_KEY_BYTES    2946
#define BIKE1_L1_R2_CIPHERTEXT_BYTES    2946
#define BIKE1_L1_R2_SHARED_SECRET_BYTES 32
