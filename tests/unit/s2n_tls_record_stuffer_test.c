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
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_record.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
#if 0
    uint8_t plaintext_pad[S2N_TLS_MAXIMUM_RECORD_LENGTH + 1];
    uint8_t encrypted_pad[S2N_TLS_MAXIMUM_RECORD_LENGTH + 1];
    uint8_t entropy[S2N_TLS_MAXIMUM_RECORD_LENGTH + 1];
    struct s2n_record_stuffer writer;
    uint8_t protocol_version[2] = { 3, 0 };

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_FAILURE(s2n_tls_record_stuffer_init(&writer, plaintext_pad, encrypted_pad, S2N_TLS_MAXIMUM_RECORD_LENGTH - 1, &error_message));
    EXPECT_SUCCESS(s2n_tls_record_stuffer_init(&writer, plaintext_pad, encrypted_pad, S2N_TLS_MAXIMUM_RECORD_LENGTH + 1, &error_message));

    /* Record is too short */
    EXPECT_FAILURE(s2n_tls_record_finalize(&writer, &error_message));

    /* Add a header */
    EXPECT_SUCCESS(s2n_tls_record_write_header(&writer, 1, protocol_version, &error_message));
    EXPECT_EQUAL(s2n_stuffer_data_available(&writer.plaintext_stuffer), S2N_TLS_MINIMUM_RECORD_LENGTH);

    /* Should now be finalizable */
    EXPECT_SUCCESS(s2n_tls_record_finalize(&writer, &error_message));

    uint8_t expected[] = { 1, 3, 0, 0, 0 };
    EXPECT_BYTEARRAY_EQUAL(plaintext_pad, expected, 5);

    /* Get some Random data */
    EXPECT_SUCCESS(s2n_get_random_data(entropy, sizeof(entropy), &error_message));

    /* Write our maximum record payload */
    EXPECT_SUCCESS(s2n_stuffer_write(&writer.plaintext_stuffer, entropy, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH, &error_message));
    EXPECT_SUCCESS(s2n_tls_record_finalize(&writer, &error_message));
    uint8_t expected2[] = { 1, 3, 0, 0x48, 0x00 };
    EXPECT_BYTEARRAY_EQUAL(plaintext_pad, expected2, 5);

    /* Try one higher, make sure it fails */
    EXPECT_SUCCESS(s2n_stuffer_write(&writer.plaintext_stuffer, entropy, 1, &error_message));
    EXPECT_FAILURE(s2n_tls_record_finalize(&writer, &error_message));

    /* Try SSL2 now ... */
    EXPECT_SUCCESS(s2n_tls_record_stuffer_init(&writer, plaintext_pad, encrypted_pad, S2N_TLS_MAXIMUM_RECORD_LENGTH + 1, &error_message));

    /* Record is too short */
    EXPECT_FAILURE(s2n_ssl2_record_finalize(&writer, &error_message));

    /* Add a header */
    EXPECT_SUCCESS(s2n_ssl2_record_write_header(&writer, 1, protocol_version, &error_message));
    EXPECT_EQUAL(s2n_stuffer_data_available(&writer.plaintext_stuffer), 5);

    /* Still not finalizeable */
    EXPECT_FAILURE(s2n_ssl2_record_finalize(&writer, &error_message));

    /* Add the 22 bytes of mandatory header data */
    EXPECT_SUCCESS(s2n_stuffer_write_uint16(&writer.plaintext_stuffer, 0, &error_message));
    EXPECT_SUCCESS(s2n_stuffer_write_uint16(&writer.plaintext_stuffer, 0, &error_message));
    EXPECT_SUCCESS(s2n_stuffer_write_uint16(&writer.plaintext_stuffer, 16, &error_message));
    EXPECT_SUCCESS(s2n_stuffer_write(&writer.plaintext_stuffer, entropy, 16, &error_message));

    /* Now we can finalize */
    EXPECT_SUCCESS(s2n_ssl2_record_finalize(&writer, &error_message));

    uint8_t expected3[] = { 0x80, 0x19, 1, 3, 0, 0, 0, 0, 0, 0, 16 };
    EXPECT_BYTEARRAY_EQUAL(plaintext_pad, expected3, 11);

    /* Write our maximum record payload */
    EXPECT_SUCCESS(s2n_stuffer_write(&writer.plaintext_stuffer, entropy, S2N_SSL2_MAXIMUM_MESSAGE_LENGTH, &error_message));
    EXPECT_SUCCESS(s2n_ssl2_record_finalize(&writer, &error_message));

    uint8_t expected4[] = { 0xbf, 0xfd, 1, 3, 0, 0, 0, 0, 0, 0, 16 };
    EXPECT_BYTEARRAY_EQUAL(plaintext_pad, expected4, 11);

    /* Try one higher, make sure it fails */
    EXPECT_SUCCESS(s2n_stuffer_write(&writer.plaintext_stuffer, entropy, 1, &error_message));
    EXPECT_FAILURE(s2n_ssl2_record_finalize(&writer, &error_message));

    END_TEST();
#endif
    return 0;
}
