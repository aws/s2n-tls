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
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_crypto.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    /* s2n_sequence_number_to_uint64 */
    {
        /* Converts zero */
        {
            uint64_t output = 1;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            struct s2n_blob sequence_number = { 0 };

            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));

            EXPECT_SUCCESS(s2n_sequence_number_to_uint64(&sequence_number, &output));

            EXPECT_EQUAL(output, 0);
        };

        /* Converts one */
        {
            uint64_t output = 0;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            data[S2N_TLS_SEQUENCE_NUM_LEN - 1] = 1;
            struct s2n_blob sequence_number = { 0 };

            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));

            EXPECT_SUCCESS(s2n_sequence_number_to_uint64(&sequence_number, &output));

            EXPECT_EQUAL(output, 1);
        };

        /* Converts max possible sequence number */
        {
            uint64_t output = 0;
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            struct s2n_blob sequence_number = { 0 };

            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_SUCCESS(s2n_blob_zero(&sequence_number));

            for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                sequence_number.data[i] = UINT8_MAX;
            }

            EXPECT_SUCCESS(s2n_sequence_number_to_uint64(&sequence_number, &output));

            EXPECT_EQUAL(output, 18446744073709551615U);
        };

        /* Converts max record number value */
        {
            uint64_t output = 0;

            /* The maximum record number converted to base 256 */
            uint8_t data[S2N_TLS_SEQUENCE_NUM_LEN] = { 0, 0, 0, 0, 1, 106, 9, 229 };
            struct s2n_blob sequence_number = { 0 };

            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, data, S2N_TLS_SEQUENCE_NUM_LEN));

            EXPECT_SUCCESS(s2n_sequence_number_to_uint64(&sequence_number, &output));

            EXPECT_EQUAL(output, S2N_TLS13_AES_GCM_MAXIMUM_RECORD_NUMBER);
        };

        /* Matches network order stuffer methods */
        {
            uint64_t input = 0x1234ABCD;

            /* Use stuffer to convert to network order */
            uint8_t stuffer_bytes[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            struct s2n_blob stuffer_blob = { 0 };
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&stuffer_blob, stuffer_bytes, sizeof(stuffer_bytes)));
            EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &stuffer_blob));
            EXPECT_SUCCESS(s2n_stuffer_write_uint64(&stuffer, input));

            /* Use s2n_sequence_number_to_uint64 to convert back */
            uint64_t output = 0;
            EXPECT_SUCCESS(s2n_sequence_number_to_uint64(&stuffer_blob, &output));

            EXPECT_EQUAL(input, output);
        };
    };
    END_TEST();
}
