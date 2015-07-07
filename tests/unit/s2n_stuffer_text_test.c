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
 */

#include "s2n_test.h"
#include <string.h>

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
#if 0
    char pad[5120];
    char text[] = "    This is some text\r\n\tmore text";
    char tokenpad[6];
    char fields[] = "one,two,three";
    char out[1024];
    char c;
    struct s2n_stuffer stuffer, token;
    struct s2n_blob pblob, tblob;

    BEGIN_TEST();

    /* Create a stuffer */
    EXPECT_SUCCESS(s2n_blob_init(&tblob, (uint8_t *)tokenpad, sizeof(tokenpad)));
    EXPECT_SUCCESS(s2n_stuffer_init(&token, &tblob));
    EXPECT_SUCCESS(s2n_blob_init(&pblob, (uint8_t *)pad, sizeof(pad)));
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &pblob));
    EXPECT_SUCCESS(s2n_stuffer_write_text(&stuffer, text, sizeof(text)));

    /* Skip 4 bytes of whitespace */
    EXPECT_EQUAL(s2n_stuffer_skip_whitespace(&stuffer), 4);

    /* Skip 4 bytes of whitespace */
    EXPECT_SUCCESS(s2n_stuffer_peek_char(&stuffer, &c));
    EXPECT_EQUAL(c, 'T');

    /* Read the next 17 chars */
    EXPECT_SUCCESS(s2n_stuffer_read_text(&stuffer, out, 17));
    EXPECT_EQUAL(memcmp(out, "This is some text", 17), 0);

    /* Skip 3 bytes of whitespace */
    EXPECT_EQUAL(s2n_stuffer_skip_whitespace(&stuffer), 3);

    /* Read the next 10 chars (including the terminating zero) */
    EXPECT_SUCCESS(s2n_stuffer_read_text(&stuffer, out, 10));
    EXPECT_EQUAL(memcmp(out, "more text", 10), 0);

    /* Test end of stream behaviour */
    EXPECT_SUCCESS(s2n_stuffer_skip_whitespace(&stuffer));
    EXPECT_FAILURE(s2n_stuffer_peek_char(&stuffer, &c));
    EXPECT_FAILURE(s2n_stuffer_read_char(&stuffer, &c));

    /* Start a new buffer */
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &pblob));
    EXPECT_SUCCESS(s2n_stuffer_write_text(&stuffer, fields, strlen(fields)));

    EXPECT_SUCCESS(s2n_stuffer_read_token(&stuffer, &token, ','));
    EXPECT_EQUAL(memcmp("one", token.blob.data, 3), 0);

    EXPECT_SUCCESS(s2n_stuffer_init(&token, &tblob));
    EXPECT_SUCCESS(s2n_stuffer_read_token(&stuffer, &token, ','));
    EXPECT_EQUAL(memcmp("two", token.blob.data, 3), 0);

    /* Check for end-of-stream termination */
    EXPECT_SUCCESS(s2n_stuffer_init(&token, &tblob));
    EXPECT_SUCCESS(s2n_stuffer_read_token(&stuffer, &token, ','));
    EXPECT_EQUAL(memcmp("three", token.blob.data, 5), 0);

    END_TEST();
#endif
    return 0;
}
