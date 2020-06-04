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

#include "crypto/s2n_sequence.h"

#include "error/s2n_errno.h"

#include "tls/s2n_crypto.h"

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    /* s2n_convert_sequence_number */
    {
        /* Converts zero */
        {
            uint64_t output = 0;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN];
            struct s2n_blob sequence_number = {0};
            
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));

            EXPECT_SUCCESS(s2n_convert_sequence_number(&sequence_number, &output));

            EXPECT_EQUAL(output, 0); 
        }

        /* Converts one */
        {
            uint64_t output = 0;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN];
            struct s2n_blob sequence_number = {0};

            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_SUCCESS(s2n_blob_zero(&sequence_number));
            sequence_number.data[7] = 1;

            EXPECT_SUCCESS(s2n_convert_sequence_number(&sequence_number, &output));
            
            EXPECT_EQUAL(output, 1); 
        }

        /* Converts max possible sequence number */
        {
            uint64_t output = 0;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN];
            struct s2n_blob sequence_number = {0};
            
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_SUCCESS(s2n_blob_zero(&sequence_number));

            for (int i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                sequence_number.data[i] = UINT8_MAX;
            }
            
            EXPECT_SUCCESS(s2n_convert_sequence_number(&sequence_number, &output));

            EXPECT_EQUAL(output, 18446744073709551615U);     
        }

        /* Converts max record number value */
        {
            uint64_t output = 0;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN];
            struct s2n_blob sequence_number = {0};
            
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_SUCCESS(s2n_blob_zero(&sequence_number));

            sequence_number.data[4] = 1;
            sequence_number.data[5] = 106;
            sequence_number.data[6] = 9;
            sequence_number.data[7] = 229;
            
            EXPECT_SUCCESS(s2n_convert_sequence_number(&sequence_number, &output));

            EXPECT_EQUAL(output, S2N_TLS13_AES_GCM_MAXIMUM_RECORD_NUMBER);   
        }
    }
    END_TEST();
}
