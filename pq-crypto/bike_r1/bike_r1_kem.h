/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
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
BIKE1_L1_R1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

// Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
// Return 0 for success and !0 for failures. See types.h for failure codes
int
BIKE1_L1_R1_crypto_kem_enc(OUT unsigned char *     ct,
                           OUT unsigned char *     ss,
                           IN const unsigned char *pk);

// Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
// Return 0 for success and !0 for failures. See types.h for failure codes
int
BIKE1_L1_R1_crypto_kem_dec(OUT unsigned char *     ss,
                           IN const unsigned char *ct,
                           IN const unsigned char *sk);

#define BIKE1_L1_R1_SECRET_KEY_BYTES    3110
#define BIKE1_L1_R1_PUBLIC_KEY_BYTES    2542
#define BIKE1_L1_R1_CIPHERTEXT_BYTES    2542
#define BIKE1_L1_R1_SHARED_SECRET_BYTES 32
