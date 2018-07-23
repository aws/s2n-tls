/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#ifndef __BIKE1_L1_KEM_H_INCLUDED__
#define __BIKE1_L1_KEM_H_INCLUDED__

////////////////////////////////////////////////////////////////
//The three APIs below (keypair, enc, dec) are defined by NIST:
////////////////////////////////////////////////////////////////
// Keygenerate - pk is the public key
//               sk is the private key
int BIKE1_L1_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
int BIKE1_L1_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
int BIKE1_L1_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif //__BIKE1_L1_KEM_H_INCLUDED__