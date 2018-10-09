/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
 *
 * Modified from PQCgenKAT_kem.c
 * Created by Bassham, Lawrence E (Fed) on 8/29/17.
 * Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
 */

#include "s2n_test.h"
#include "s2n_nist_kats.h"
#include "pq-crypto/bike/bike1_l1_kem.h"
#include "pq-crypto/pq-random.h"
#include "./crypto/s2n_fips.c"

#define RSP_FILE_NAME "kats/bike1_l1.kat"

int main(int argc, char **argv, char **envp) {
    BEGIN_TEST();

    // BIKE is not supported in FIPS mode
    if (s2n_is_in_fips_mode()) {
        END_TEST();
    }

    // Flip pq-random over to nist RNG to ensure KAT values match
    EXPECT_SUCCESS(initialize_pq_crypto_generator(&randombytes));

    FILE *rsp_file = fopen(RSP_FILE_NAME, "r");
    EXPECT_NOT_NULL(rsp_file);

    int count;
    uint8_t seed[48];

    // Client side variables
    uint8_t ct[BIKE1_L1_CIPHERTEXT_BYTES];
    uint8_t client_shared_secret[BIKE1_L1_SHARED_SECRET_BYTES];

    // Server side variables
    uint8_t pk[BIKE1_L1_PUBLIC_KEY_BYTES];
    uint8_t sk[BIKE1_L1_SECRET_KEY_BYTES];
    uint8_t server_shared_secret[BIKE1_L1_SHARED_SECRET_BYTES];

    // Known answer variables
    uint8_t pk_answer[BIKE1_L1_PUBLIC_KEY_BYTES];
    uint8_t sk_answer[BIKE1_L1_SECRET_KEY_BYTES];
    uint8_t ct_answer[BIKE1_L1_CIPHERTEXT_BYTES];
    uint8_t shared_secret_answer[BIKE1_L1_SHARED_SECRET_BYTES];

    for (uint32_t i = 0; i < NUM_OF_KATS; i++) {
        // Verify test index
        EXPECT_SUCCESS(FindMarker(rsp_file, "count = "));
        EXPECT_TRUE(fscanf(rsp_file, "%d", &count) > 0);
        EXPECT_EQUAL(count, i);

        // Set the NIST rng to the same state the response file was created with
        EXPECT_SUCCESS(ReadHex(rsp_file, seed, 48, "seed = "));
        randombytes_init(seed, NULL, 256);

        ////////////////////////////////////
        //      Run the prtocol
        ////////////////////////////////////

        // Generate the public/private key pair
        EXPECT_SUCCESS(BIKE1_L1_crypto_kem_keypair(pk, sk));

        // Create a shared secret and use the public key to encrypt it
        EXPECT_SUCCESS(BIKE1_L1_crypto_kem_enc(ct, client_shared_secret, pk));

        // Use the private key to decrypt the ct to get the shared secret
        EXPECT_SUCCESS(BIKE1_L1_crypto_kem_dec(server_shared_secret, ct, sk));

        ////////////////////////////////////
        //      Verify the results
        ////////////////////////////////////

        // Read the KAT values
        EXPECT_SUCCESS(ReadHex(rsp_file, pk_answer, BIKE1_L1_PUBLIC_KEY_BYTES, "pk = "));
        EXPECT_SUCCESS(ReadHex(rsp_file, sk_answer, BIKE1_L1_SECRET_KEY_BYTES, "sk = "));
        EXPECT_SUCCESS(ReadHex(rsp_file, ct_answer, BIKE1_L1_CIPHERTEXT_BYTES, "ct = "));
        EXPECT_SUCCESS(ReadHex(rsp_file, shared_secret_answer, BIKE1_L1_SHARED_SECRET_BYTES, "ss = "));

        // Test the client and server got the same value
        EXPECT_BYTEARRAY_EQUAL(client_shared_secret, server_shared_secret, BIKE1_L1_SHARED_SECRET_BYTES);

        // Compare the KAT values
        EXPECT_BYTEARRAY_EQUAL(pk_answer, pk, BIKE1_L1_PUBLIC_KEY_BYTES);
        EXPECT_BYTEARRAY_EQUAL(sk_answer, sk, BIKE1_L1_SECRET_KEY_BYTES);
        EXPECT_BYTEARRAY_EQUAL(ct_answer, ct, BIKE1_L1_CIPHERTEXT_BYTES);
        EXPECT_BYTEARRAY_EQUAL(shared_secret_answer, server_shared_secret, BIKE1_L1_SHARED_SECRET_BYTES);
    }

    fclose(rsp_file);

    END_TEST();
}
