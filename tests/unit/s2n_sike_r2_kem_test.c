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
#include "pq-crypto/s2n_pq.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

#if !defined(S2N_NO_PQ)

    unsigned char pub_key[SIKE_P434_R2_PUBLIC_KEY_BYTES] = {0};
    unsigned char priv_key[SIKE_P434_R2_SECRET_KEY_BYTES] = {0};
    unsigned char c_shared_secret[SIKE_P434_R2_SHARED_SECRET_BYTES] = {0};
    unsigned char s_shared_secret[SIKE_P434_R2_SHARED_SECRET_BYTES] = {0};
    unsigned char ciphertext[SIKE_P434_R2_CIPHERTEXT_BYTES] = {0};

    /* Test the portable C code */
    {
        EXPECT_OK(s2n_disable_sikep434r2_asm());
        EXPECT_FALSE(s2n_sikep434r2_asm_is_enabled());

        EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_keypair(pub_key, priv_key));
        EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_enc(ciphertext, c_shared_secret, pub_key));
        EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_dec(s_shared_secret, ciphertext, priv_key));
        EXPECT_BYTEARRAY_EQUAL(s_shared_secret, c_shared_secret, SIKE_P434_R2_SHARED_SECRET_BYTES);
    }

    /* Test the assembly, if available; if not, don't bother testing the C again */
    EXPECT_OK(s2n_try_enable_sikep434r2_asm());
    if (s2n_sikep434r2_asm_is_enabled()) {
        memset_check((unsigned char *)pub_key, 0, SIKE_P434_R2_PUBLIC_KEY_BYTES);
        memset_check((unsigned char *)priv_key, 0, SIKE_P434_R2_SECRET_KEY_BYTES);
        memset_check((unsigned char *)c_shared_secret, 0, SIKE_P434_R2_SHARED_SECRET_BYTES);
        memset_check((unsigned char *)s_shared_secret, 0, SIKE_P434_R2_SHARED_SECRET_BYTES);
        memset_check((unsigned char *)ciphertext, 0, SIKE_P434_R2_CIPHERTEXT_BYTES);

        EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_keypair(pub_key, priv_key));
        EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_enc(ciphertext, c_shared_secret, pub_key));
        EXPECT_SUCCESS(SIKE_P434_r2_crypto_kem_dec(s_shared_secret, ciphertext, priv_key));
        EXPECT_BYTEARRAY_EQUAL(s_shared_secret, c_shared_secret, SIKE_P434_R2_SHARED_SECRET_BYTES);
    }


#endif

    END_TEST();
}
