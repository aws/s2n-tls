/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "crypto/s2n_fips.h"
#include "pq-crypto/bike_r2/bike_r2_kem.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    unsigned char publicKey[BIKE1_L1_R2_PUBLIC_KEY_BYTES];
    unsigned char privateKey[BIKE1_L1_R2_SECRET_KEY_BYTES];
    unsigned char clientSharedSecretPlaintext[BIKE1_L1_R2_SHARED_SECRET_BYTES];
    unsigned char serverSharedSecretPlaintext[BIKE1_L1_R2_SHARED_SECRET_BYTES];
    unsigned char encryptedSecret[BIKE1_L1_R2_CIPHERTEXT_BYTES];

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }

    EXPECT_SUCCESS(BIKE1_L1_R2_crypto_kem_keypair(publicKey, privateKey));
    EXPECT_SUCCESS(BIKE1_L1_R2_crypto_kem_enc(encryptedSecret, clientSharedSecretPlaintext, publicKey));
    EXPECT_SUCCESS(BIKE1_L1_R2_crypto_kem_dec(serverSharedSecretPlaintext, encryptedSecret, privateKey));
    EXPECT_BYTEARRAY_EQUAL(serverSharedSecretPlaintext, clientSharedSecretPlaintext, BIKE1_L1_R2_SHARED_SECRET_BYTES);

#endif
    END_TEST();
}

