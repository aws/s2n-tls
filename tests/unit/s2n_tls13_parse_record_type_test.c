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

#include <stdint.h>
#include <stdlib.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_record.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    uint8_t record_type;

    /* In tls13 the true record type is inserted in the last byte of the encrypted payload. This
    * test creates a fake unencrypted payload and checks that the helper function
    * s2n_tls13_parse_record_type() correctly parses the type.
    */
    {
        uint16_t plaintext = 0xdaf3;
        struct s2n_stuffer plaintext_stuffer = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&plaintext_stuffer, sizeof(plaintext)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&plaintext_stuffer, plaintext));
        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&plaintext_stuffer, &record_type));
        EXPECT_EQUAL(record_type, 0xf3);
        EXPECT_EQUAL(s2n_stuffer_data_available(&plaintext_stuffer), 1);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&plaintext_stuffer));
    }

    /* Test for failure when stuffer is completely empty */
    {
        struct s2n_stuffer empty_stuffer = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&empty_stuffer, 0));
        EXPECT_FAILURE(s2n_tls13_parse_record_type(&empty_stuffer, &record_type));
    };

    /* Test for case where there is a record type in the stuffer but no content */
    {
        uint16_t plaintext = 0xf3;
        struct s2n_stuffer plaintext_stuffer = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&plaintext_stuffer, sizeof(plaintext)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&plaintext_stuffer, plaintext));
        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&plaintext_stuffer, &record_type));
        EXPECT_EQUAL(record_type, 0xf3);
        EXPECT_EQUAL(s2n_stuffer_data_available(&plaintext_stuffer), 1);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&plaintext_stuffer));
    };

    /* Test for record padding handling */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        /* no padding */
        S2N_BLOB_FROM_HEX(padding_0, "16");
        EXPECT_SUCCESS(s2n_stuffer_write(&stuffer, &padding_0));
        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
        EXPECT_EQUAL(record_type, 0x16);

        /* 1 byte padding */
        S2N_BLOB_FROM_HEX(padding_1, "1600");
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write(&stuffer, &padding_1));
        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
        EXPECT_EQUAL(record_type, 0x16);

        /* 2 byte padding */
        S2N_BLOB_FROM_HEX(padding_2, "160000");
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write(&stuffer, &padding_2));
        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
        EXPECT_EQUAL(record_type, 0x16);

        /** test: padding without record type should fail
         * 
         *= https://tools.ietf.org/rfc/rfc8446#section-5.4
         *= type=test
         *# If a receiving implementation does not
         *# find a non-zero octet in the cleartext, it MUST terminate the
         *# connection with an "unexpected_message" alert.
         **/
        S2N_BLOB_FROM_HEX(no_type, "00");
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write(&stuffer, &no_type));
        EXPECT_FAILURE(s2n_tls13_parse_record_type(&stuffer, &record_type));

        /* multiple padding without record type should fail */
        S2N_BLOB_FROM_HEX(no_type2, "0000");
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write(&stuffer, &no_type2));
        EXPECT_FAILURE(s2n_tls13_parse_record_type(&stuffer, &record_type));

        /* empty stuffer should fail */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_FAILURE(s2n_tls13_parse_record_type(&stuffer, &record_type));

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Defining these here as variables as they aren't used in prior tests. */
    const uint8_t padding_value = 0x00;
    const uint8_t not_padding_value = 0x16;

    /* Test maximum record length size (empty data) */
    {
        EXPECT_EQUAL(S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH, 16385);

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, not_padding_value));

        /* fill up stuffer to before the limit */
        while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, padding_value));
        }
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH);

        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
        EXPECT_EQUAL(record_type, not_padding_value);
        /* There was no data before the record type */
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    /* Test maximum record length size (maximum data) */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        /* fill up stuffer to before the limit */
        while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, not_padding_value));
        }
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH);

        EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
        EXPECT_EQUAL(record_type, not_padding_value);
        /* The last byte is stripped as the content type */
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH - 1);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    /* Certain versions of Java can generate inner plaintexts with lengths up to
     * S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + 16 (See JDK-8221253)
     * However, after the padding is stripped, the result will always be no more than
     * S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH - 1
     */
    {
        const size_t extra_length_tolerated = 16;
        /* Test slightly overlarge record for compatibility (empty data) */
        {
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, not_padding_value));
            /* fill up stuffer the limit  + 16 */
            while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, padding_value));
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated);
            EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
            EXPECT_EQUAL(record_type, not_padding_value);
            /* There was no data before the record type */
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        }

        /* Test slightly overlarge record for compatibility (maximum data) */
        {
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

            /* fill up stuffer to before the limit */
            while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, not_padding_value));
            }
            /* pad up stuffer the limit  + 16 */
            while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, padding_value));
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated);

            EXPECT_SUCCESS(s2n_tls13_parse_record_type(&stuffer, &record_type));
            EXPECT_EQUAL(record_type, not_padding_value);
            /* The last byte is stripped as the content type */
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH - 1);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        }

        /* Test slightly overlarge record for compatibility (with too much data) */
        {
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

            /* Finally, do this with an overall length which should pass, but too much data before the padding */
            /* fill up stuffer to the maximum amount of data */
            while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, padding_value));
            }
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, not_padding_value)); /* Record type */
            /* 16 bytes of padding*/
            while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, padding_value));
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated);
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_parse_record_type(&stuffer, &record_type), S2N_ERR_MAX_INNER_PLAINTEXT_SIZE);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        }

        /* Test slightly overlarge + 1 record for compatibility (empty data) */
        {
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, not_padding_value));
            while (s2n_stuffer_data_available(&stuffer) < S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated + 1) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, padding_value));
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + extra_length_tolerated + 1);

            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_parse_record_type(&stuffer, &record_type), S2N_ERR_MAX_INNER_PLAINTEXT_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        }
    }
    END_TEST();
}
