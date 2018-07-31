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
 *
 * Modified from PQCgenKAT_kem.c
 * Created by Bassham, Lawrence E (Fed) on 8/29/17.
 * Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>

#include "s2n_test.h"
#include "crypto/s2n_fips.h"
#include "pq-crypto/bike/bike1_l1_kem.h"
#include "testlib/nist_rng.h"

#define MAX_MARKER_LEN 50

int FindMarker(FILE *infile, const char *marker);

int ReadHex(FILE *infile, unsigned char *result, int length, const char *marker);

int main(int argc, char **argv, char **envp) {
    BEGIN_TEST();
    // BIKE is not supported in FIPS mode
    if (s2n_is_in_fips_mode()) {
        END_TEST();
    }

    char request_file_name[] = "PQCkemKAT_BIKE1-Level1_2542.rsp";
    FILE *request_file = fopen(request_file_name, "r");

    int count;
    unsigned char seed[48];
    // Client side variables
    unsigned char ciphertext[BIKE1_L1_CIPHERTEXT_BYTES],
            client_shared_secret[BIKE1_L1_SHARED_SECRET_BYTES];
    // Server side variables
    unsigned char public_key[BIKE1_L1_PUBLIC_KEY_BYTES],
            server_secret_key[BIKE1_L1_SECRET_KEY_BYTES],
            server_shared_secret[BIKE1_L1_SHARED_SECRET_BYTES];
    // Known answer variables
    unsigned char public_key_answer[BIKE1_L1_PUBLIC_KEY_BYTES],
            server_secret_key_answer[BIKE1_L1_SECRET_KEY_BYTES],
            ciphertext_answer[BIKE1_L1_CIPHERTEXT_BYTES],
            shared_secret_answer[BIKE1_L1_SHARED_SECRET_BYTES];

    for (int i = 0; i <100; i++) {
        EXPECT_SUCCESS(FindMarker(request_file, "count = "));
        EXPECT_TRUE(fscanf(request_file, "%d", &count) > 0);
        EXPECT_EQUAL(count, i);

        EXPECT_SUCCESS(ReadHex(request_file, seed, 48, "seed = "));
        EXPECT_SUCCESS(ReadHex(request_file, public_key_answer, BIKE1_L1_PUBLIC_KEY_BYTES, "pk = "));
        EXPECT_SUCCESS(ReadHex(request_file, server_secret_key_answer, BIKE1_L1_SECRET_KEY_BYTES, "sk = "));
        EXPECT_SUCCESS(ReadHex(request_file, ciphertext_answer, BIKE1_L1_CIPHERTEXT_BYTES, "ct = "));
        EXPECT_SUCCESS(ReadHex(request_file, shared_secret_answer, BIKE1_L1_SHARED_SECRET_BYTES, "ss = "));

        // Set the NIST rng to the same state the response file was created with
        randombytes_init(seed, NULL, 256);

        // Generate the public/private key pair
        EXPECT_SUCCESS(BIKE1_L1_crypto_kem_keypair(public_key, server_secret_key));

        // Create a shared secret and use the public key to encrypt it
        EXPECT_SUCCESS(BIKE1_L1_crypto_kem_enc(ciphertext, client_shared_secret, public_key));

        // Use the private key to decrypt the ciphertext to get the shared secret
        EXPECT_SUCCESS(BIKE1_L1_crypto_kem_dec(server_shared_secret, ciphertext, server_secret_key));

        // Test the client and server got the same value
        EXPECT_BYTEARRAY_EQUAL(client_shared_secret, server_shared_secret, BIKE1_L1_SHARED_SECRET_BYTES);

        // Check the known answer values for the given seed
        EXPECT_BYTEARRAY_EQUAL(public_key_answer, public_key, BIKE1_L1_PUBLIC_KEY_BYTES);
        EXPECT_BYTEARRAY_EQUAL(server_secret_key_answer, server_secret_key, BIKE1_L1_SECRET_KEY_BYTES);
        EXPECT_BYTEARRAY_EQUAL(ciphertext_answer, ciphertext, BIKE1_L1_CIPHERTEXT_BYTES);
        EXPECT_BYTEARRAY_EQUAL(shared_secret_answer, server_shared_secret, BIKE1_L1_SHARED_SECRET_BYTES);
    }

    fclose(request_file);

    END_TEST();
}


//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
    char	line[MAX_MARKER_LEN];
    int		i, len;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
        if ( (line[i] = fgetc(infile)) == EOF )
            return 0;
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        if ( (line[len-1] = fgetc(infile)) == EOF )
            return 0;
        line[len] = '\0';
    }
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, const char *str)
{
    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    if ( FindMarker(infile, str) )
    {
        int ch;
        int started = 0;
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) {
                    if (ch == '\n')
                        break;
                    else
                        continue;
                } else
                    break;
            }
            started = 1;
            unsigned char ich;
            if ((ch >= '0') && (ch <= '9'))
                ich = ch - '0';
            else if ((ch >= 'A') && (ch <= 'F'))
                ich = ch - 'A' + 10;
            else if ((ch >= 'a') && (ch <= 'f'))
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

            for (int i = 0; i < Length - 1; i++)
                A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    }
    else
    {
        return 0;
    }
    return 1;
}