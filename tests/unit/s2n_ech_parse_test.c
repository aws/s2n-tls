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

#include "tls/s2n_ech_parse.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Each read returns the value and advances past it */
    {
        S2N_BLOB_FROM_HEX(input, "01"
                                 "0203"
                                 "02"
                                 "0405"
                                 "0003"
                                 "060708"
                                 "090a");
        struct s2n_stuffer in = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &input));

        uint8_t u8 = 0;
        EXPECT_OK(s2n_ech_read_uint8(&in, &u8, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(u8, 0x01);

        uint16_t u16 = 0;
        EXPECT_OK(s2n_ech_read_uint16(&in, &u16, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(u16, 0x0203);

        struct s2n_blob vector = { 0 };
        EXPECT_OK(s2n_ech_read_uint8_vector(&in, &vector, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(vector.size, 2);
        EXPECT_EQUAL(vector.data, input.data + 4);

        EXPECT_OK(s2n_ech_read_uint16_vector(&in, &vector, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(vector.size, 3);
        EXPECT_EQUAL(vector.data, input.data + 8);

        struct s2n_blob bytes = { 0 };
        EXPECT_OK(s2n_ech_read_bytes(&in, 2, &bytes, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(bytes.size, 2);
        EXPECT_EQUAL(bytes.data, input.data + 11);

        EXPECT_EQUAL(s2n_stuffer_data_available(&in), 0);
    };

    /* An extension is read as its type, its body, and the whole extension */
    {
        S2N_BLOB_FROM_HEX(input, "1234"
                                 "0002"
                                 "abcd"
                                 "5678"
                                 "0000");
        struct s2n_stuffer in = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &input));

        uint16_t type = 0;
        struct s2n_blob body = { 0 };
        struct s2n_blob extension = { 0 };
        EXPECT_OK(s2n_ech_read_extension(&in, &type, &body, &extension, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(type, 0x1234);
        EXPECT_EQUAL(body.size, 2);
        EXPECT_EQUAL(body.data, input.data + 4);
        EXPECT_EQUAL(extension.size, 6);
        EXPECT_EQUAL(extension.data, input.data);

        /* The whole extension is optional */
        EXPECT_OK(s2n_ech_read_extension(&in, &type, &body, NULL, S2N_ERR_ECH_INVALID_CONFIG));
        EXPECT_EQUAL(type, 0x5678);
        EXPECT_EQUAL(body.size, 0);
        EXPECT_EQUAL(s2n_stuffer_data_available(&in), 0);
    };

    /* Every read of a short input fails with the given error */
    {
        const s2n_error errors[] = { S2N_ERR_ECH_INVALID_CONFIG, S2N_ERR_BAD_MESSAGE };
        for (size_t i = 0; i < s2n_array_len(errors); i++) {
            s2n_error error = errors[i];
            S2N_BLOB_FROM_HEX(input, "00");
            struct s2n_stuffer in = { 0 };
            uint8_t u8 = 0;
            uint16_t u16 = 0;
            struct s2n_blob blob = { 0 };

            EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &input));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&in, 1));
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_read_uint8(&in, &u8, error), error);

            EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &input));
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_read_uint16(&in, &u16, error), error);

            EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &input));
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_read_bytes(&in, 2, &blob, error), error);

            S2N_BLOB_FROM_HEX(short_uint8_vector, "02"
                                                  "00");
            EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &short_uint8_vector));
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_read_uint8_vector(&in, &blob, error), error);

            S2N_BLOB_FROM_HEX(short_uint16_vector, "0002"
                                                   "00");
            EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &short_uint16_vector));
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_read_uint16_vector(&in, &blob, error), error);

            /* An extension cut off in its type, its length, or its body */
            const char *short_extensions[] = { "12", "1234", "1234"
                                                             "00",
                "1234"
                "0002"
                "00" };
            for (size_t j = 0; j < s2n_array_len(short_extensions); j++) {
                S2N_BLOB_FROM_HEX(short_extension, short_extensions[j]);
                EXPECT_SUCCESS(s2n_stuffer_init_written(&in, &short_extension));
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_read_extension(&in, &u16, &blob, NULL, error), error);
            }
        }
    };

    END_TEST();
}
