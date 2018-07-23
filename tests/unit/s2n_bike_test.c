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

#include "s2n_test.h"

#include "pq-crypto/bike/bike1_l1_kem.h"

#define bike1_l1_length_secret_key 2542
#define bike1_l1_length_public_key 2542
#define bike1_l1_length_ciphertext 2542
#define bike1_l1_length_shared_secret 32

uint32_t constant_time_compare(const uint8_t* a,
                  const uint8_t* b,
                  const uint32_t size)
{
    volatile uint8_t res = 0;

    for(uint32_t i=0; i < size; ++i)
    {
        res |= (a[i] ^ b[i]);
    }

    return (res == 0);
}

int main(int argc, char **argv)
{
    unsigned char publicKey[bike1_l1_length_public_key];
    unsigned char privateKey[bike1_l1_length_secret_key];
    unsigned char clientSharedSecretPlaintext[bike1_l1_length_shared_secret];
    unsigned char serverSharedSecretPlaintext[bike1_l1_length_shared_secret];
    unsigned char encryptedSecret[bike1_l1_length_ciphertext];


    BEGIN_TEST();

    EXPECT_SUCCESS(BIKE1_L1_crypto_kem_keypair(publicKey, privateKey));
    EXPECT_SUCCESS(BIKE1_L1_crypto_kem_enc(encryptedSecret, clientSharedSecretPlaintext, publicKey));
    EXPECT_SUCCESS(BIKE1_L1_crypto_kem_dec(serverSharedSecretPlaintext, encryptedSecret, privateKey));
    EXPECT_TRUE(constant_time_compare(serverSharedSecretPlaintext, clientSharedSecretPlaintext, bike1_l1_length_shared_secret));
    EXPECT_FALSE(constant_time_compare(privateKey, publicKey, bike1_l1_length_public_key));

    END_TEST();
}