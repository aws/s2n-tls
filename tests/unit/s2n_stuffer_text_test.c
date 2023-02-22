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

#include <string.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    char c;
    uint32_t skipped = 0;
    struct s2n_stuffer stuffer, token;
    struct s2n_blob pad_blob, token_blob;
    char text[] = "    This is some text\r\n\tmore text";
    char fields[] = "one,two,three";
    uint8_t pad[1024];
    char out[1024];
    char tokenpad[6];

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Check whitespace reading */
    {
        /* Create a stuffer */
        EXPECT_SUCCESS(s2n_blob_init(&token_blob, (uint8_t *) tokenpad, sizeof(tokenpad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &token_blob));
        EXPECT_SUCCESS(s2n_blob_init(&pad_blob, (uint8_t *) pad, sizeof(pad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_write_text(&stuffer, text, sizeof(text)));

        /* Skip 4 bytes of whitespace */
        EXPECT_SUCCESS(s2n_stuffer_skip_whitespace(&stuffer, &skipped));
        EXPECT_EQUAL(skipped, 4);
        EXPECT_SUCCESS(s2n_stuffer_peek_char(&stuffer, &c));
        EXPECT_EQUAL(c, 'T');

        /* Read the next 17 chars */
        EXPECT_SUCCESS(s2n_stuffer_read_text(&stuffer, out, 17));
        EXPECT_EQUAL(memcmp(out, "This is some text", 17), 0);

        /* Skip 3 bytes of whitespace */
        EXPECT_SUCCESS(s2n_stuffer_skip_whitespace(&stuffer, &skipped));
        EXPECT_EQUAL(skipped, 3);

        /* Read the next 10 chars (including the terminating zero) */
        EXPECT_SUCCESS(s2n_stuffer_read_text(&stuffer, out, 10));
        EXPECT_EQUAL(memcmp(out, "more text", 10), 0);

        /* Test end of stream behaviour */
        EXPECT_SUCCESS(s2n_stuffer_skip_whitespace(&stuffer, NULL));
        EXPECT_FAILURE(s2n_stuffer_peek_char(&stuffer, &c));
        EXPECT_FAILURE(s2n_stuffer_read_char(&stuffer, &c));
    };

    /* Check read_until, rewinding, and expecting */
    {
        /* Create a stuffer */
        EXPECT_SUCCESS(s2n_blob_init(&token_blob, (uint8_t *) tokenpad, sizeof(tokenpad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &token_blob));
        EXPECT_SUCCESS(s2n_blob_init(&pad_blob, (uint8_t *) pad, sizeof(pad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_write_text(&stuffer, text, sizeof(text)));

        char target[] = "text";
        char non_target[] = "someStringNotInStuffer";
        EXPECT_SUCCESS(s2n_stuffer_skip_read_until(&stuffer, target));
        EXPECT_EQUAL(stuffer.read_cursor, 21);
        EXPECT_SUCCESS(s2n_stuffer_rewind_read(&stuffer, strlen(target)));
        EXPECT_EQUAL(stuffer.read_cursor, 17);
        EXPECT_SUCCESS(s2n_stuffer_read_expected_str(&stuffer, target));
        EXPECT_EQUAL(stuffer.read_cursor, 21);
        EXPECT_SUCCESS(s2n_stuffer_skip_read_until(&stuffer, target));
        EXPECT_EQUAL(stuffer.read_cursor, 33);
        EXPECT_FAILURE(s2n_stuffer_rewind_read(&stuffer, 99));
        EXPECT_SUCCESS(s2n_stuffer_reread(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_skip_read_until(&stuffer, non_target));
        EXPECT_EQUAL(stuffer.read_cursor, stuffer.write_cursor - strlen(non_target) + 1);
    };

    /* Check token reading */
    {
        /* Start a new buffer */
        EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_write_text(&stuffer, fields, strlen(fields)));

        EXPECT_SUCCESS(s2n_stuffer_read_token(&stuffer, &token, ','));
        EXPECT_EQUAL(memcmp("one", token.blob.data, 3), 0);

        EXPECT_SUCCESS(s2n_stuffer_init(&token, &token_blob));
        EXPECT_SUCCESS(s2n_stuffer_read_token(&stuffer, &token, ','));
        EXPECT_EQUAL(memcmp("two", token.blob.data, 3), 0);

        /* Check for end-of-stream termination */
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &token_blob));
        EXPECT_SUCCESS(s2n_stuffer_read_token(&stuffer, &token, ','));
        EXPECT_EQUAL(memcmp("three", token.blob.data, 5), 0);
    };

    /* Check line reading */
    {
        struct s2n_blob line_blob = { 0 };
        struct s2n_stuffer lstuffer = { 0 };
        char lf_line[] = "a LF terminated line\n";
        char crlf_line[] = "a CRLF terminated line\r\n";
        char lf_line_trailing_cr[] = "a LF terminated line with trailing CR\n\r\r\r\r\r\r";
        char not_a_line[] = "not a line";

        EXPECT_SUCCESS(s2n_blob_init(&line_blob, (uint8_t *) lf_line, sizeof(lf_line)));
        EXPECT_SUCCESS(s2n_stuffer_init(&lstuffer, &line_blob));
        EXPECT_SUCCESS(s2n_stuffer_write(&lstuffer, &line_blob));
        memset(pad, 0, sizeof(pad));
        EXPECT_SUCCESS(s2n_blob_init(&pad_blob, pad, sizeof(pad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_read_line(&lstuffer, &token));
        EXPECT_EQUAL(strlen("a LF terminated line"), s2n_stuffer_data_available(&token));
        EXPECT_SUCCESS(memcmp("a LF terminated line", token.blob.data, s2n_stuffer_data_available(&token)));

        EXPECT_SUCCESS(s2n_blob_init(&line_blob, (uint8_t *) crlf_line, sizeof(crlf_line)));
        EXPECT_SUCCESS(s2n_stuffer_init(&lstuffer, &line_blob));
        EXPECT_SUCCESS(s2n_stuffer_write(&lstuffer, &line_blob));
        memset(pad, 0, sizeof(pad));
        EXPECT_SUCCESS(s2n_blob_init(&pad_blob, pad, sizeof(pad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_read_line(&lstuffer, &token));
        EXPECT_EQUAL(strlen("a CRLF terminated line"), s2n_stuffer_data_available(&token));
        EXPECT_SUCCESS(memcmp("a CRLF terminated line", token.blob.data, s2n_stuffer_data_available(&token)));

        EXPECT_SUCCESS(s2n_blob_init(&line_blob, (uint8_t *) lf_line_trailing_cr, sizeof(lf_line_trailing_cr)));
        EXPECT_SUCCESS(s2n_stuffer_init(&lstuffer, &line_blob));
        EXPECT_SUCCESS(s2n_stuffer_write(&lstuffer, &line_blob));
        memset(pad, 0, sizeof(pad));
        EXPECT_SUCCESS(s2n_blob_init(&pad_blob, pad, sizeof(pad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_read_line(&lstuffer, &token));
        EXPECT_EQUAL(strlen("a LF terminated line with trailing CR"), s2n_stuffer_data_available(&token));
        EXPECT_SUCCESS(memcmp("a LF terminated line with trailing CR", token.blob.data, s2n_stuffer_data_available(&token)));

        EXPECT_SUCCESS(s2n_blob_init(&line_blob, (uint8_t *) not_a_line, sizeof(not_a_line)));
        EXPECT_SUCCESS(s2n_stuffer_init(&lstuffer, &line_blob));
        EXPECT_SUCCESS(s2n_stuffer_write(&lstuffer, &line_blob));
        memset(pad, 0, sizeof(pad));
        EXPECT_SUCCESS(s2n_blob_init(&pad_blob, pad, sizeof(pad)));
        EXPECT_SUCCESS(s2n_stuffer_init(&token, &pad_blob));
        EXPECT_SUCCESS(s2n_stuffer_read_line(&lstuffer, &token));
        EXPECT_EQUAL(sizeof(not_a_line), s2n_stuffer_data_available(&token));
        EXPECT_SUCCESS(memcmp("not a line", token.blob.data, s2n_stuffer_data_available(&token)));
    };

    END_TEST();
    return 0;
}
