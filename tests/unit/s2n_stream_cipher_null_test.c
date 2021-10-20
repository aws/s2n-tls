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

#include "api/s2n.h"
#include "s2n_test.h"
#include "crypto/s2n_stream_cipher_null.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    /* Test that in and out being the same size succeeds */
    {
        uint8_t array[9] = {0};
        struct s2n_blob in = {.data = array, .size = 9 };
        struct s2n_blob out = {.data = array, .size = 9 };
        EXPECT_SUCCESS(s2n_stream_cipher_null_endecrypt(NULL, &in, &out));
    }

    /* Test that in size > out size fails */
    {
        uint8_t array[9] = {0};
        struct s2n_blob in = {.data = array, .size = 9 };
        struct s2n_blob out = {.data = array, .size = 8 };
        EXPECT_FAILURE(s2n_stream_cipher_null_endecrypt(NULL, &in, &out));
    }

    /* Test that in is copied to out when they are different */
    {
        uint8_t in_array[9] = {0,1,2,3,4,5,6,7,8};
        uint8_t out_array[9] = {0};
        struct s2n_blob in = {.data = in_array, .size = 9 };
        struct s2n_blob out = {.data = out_array, .size = 9 };
        EXPECT_BYTEARRAY_NOT_EQUAL(in_array, out_array, out.size);
        EXPECT_SUCCESS(s2n_stream_cipher_null_endecrypt(NULL, &in, &out));
        EXPECT_BYTEARRAY_EQUAL(in_array, out_array, out.size);
    }

    END_TEST();
}
