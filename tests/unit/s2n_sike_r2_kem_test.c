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
#include "pq-crypto/sike_r2/sike_r2_kem.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    unsigned char pub_key[SIKE_P434_R2_PUBLIC_KEY_BYTES] = {0};
    unsigned char priv_key[SIKE_P434_R2_SECRET_KEY_BYTES] = {0};
    unsigned char c_shared_secret[SIKE_P434_R2_SHARED_SECRET_BYTES];
    unsigned char s_shared_secret[SIKE_P434_R2_SHARED_SECRET_BYTES];
    unsigned char ciphertext[SIKE_P434_R2_CIPHERTEXT_BYTES];

    EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_keypair(pub_key, priv_key));
    EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_enc(ciphertext, c_shared_secret, pub_key));
    EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_dec(s_shared_secret, ciphertext, priv_key));
    EXPECT_BYTEARRAY_EQUAL(s_shared_secret, c_shared_secret, SIKE_P434_R2_SHARED_SECRET_BYTES);

#endif

    END_TEST();
}
