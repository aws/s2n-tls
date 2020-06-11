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

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

int s2n_stuffer_peek_char(struct s2n_stuffer *s2n_stuffer, char *c)
{
    int r = s2n_stuffer_read_uint8(s2n_stuffer, (uint8_t *) c);
    if (r == S2N_SUCCESS) {
        s2n_stuffer->read_cursor--;
    }
    POSTCONDITION_POSIX(s2n_stuffer_is_valid(s2n_stuffer));
    return r;
}

/* Peeks in stuffer to see if expected string is present. */
int s2n_stuffer_peek_check_for_str(struct s2n_stuffer *s2n_stuffer, const char *expected)
{
    int orig_read_pos = s2n_stuffer->read_cursor;
    int rc = s2n_stuffer_read_expected_str(s2n_stuffer, expected);
    s2n_stuffer->read_cursor = orig_read_pos;

    if (rc == 0) {
        return 1;
    }
    return 0;
}

int s2n_stuffer_skip_whitespace(struct s2n_stuffer *s2n_stuffer)
{
    int skipped = 0;
    while (s2n_stuffer->read_cursor < s2n_stuffer->write_cursor) {
        switch (s2n_stuffer->blob.data[s2n_stuffer->read_cursor]) {
        case ' ':              /* We don't use isspace, because it changes under locales */
        case '\t':
        case '\n':
        case '\r':
            s2n_stuffer->read_cursor += 1;
            skipped += 1;
            break;
        default:
            return skipped;
        }
    }

    return skipped;
}

int s2n_stuffer_read_expected_str(struct s2n_stuffer *stuffer, const char *expected)
{
    void *actual = s2n_stuffer_raw_read(stuffer, strlen(expected));
    notnull_check(actual);
    S2N_ERROR_IF(memcmp(actual, expected, strlen(expected)), S2N_ERR_STUFFER_NOT_FOUND);
    return 0;
}

/* Read from stuffer until the target string is found, or until there is no more data. */
int s2n_stuffer_skip_read_until(struct s2n_stuffer *stuffer, const char *target)
{
    int len = strlen(target);
    while (s2n_stuffer_data_available(stuffer) >= len) {
        GUARD(s2n_stuffer_skip_to_char(stuffer, target[0]));
        char *actual = s2n_stuffer_raw_read(stuffer, len);
        notnull_check(actual);

        if (strncmp(actual, target, len) == 0){
            return 0;
        } else {
            /* If string doesn't match, rewind stuffer to 1 byte after last read */
            GUARD(s2n_stuffer_rewind_read(stuffer, len - 1));
            continue;
        }
    }

    return 0;

}

/* Skips the stuffer until the first instance of the target character or until there is no more data. */
int s2n_stuffer_skip_to_char(struct s2n_stuffer *stuffer, const char target)
{
    while (s2n_stuffer_data_available(stuffer) > 0) {
        char c;
        GUARD(s2n_stuffer_peek_char(stuffer, &c));
        if (c == target) {
            break;
        }

        GUARD(s2n_stuffer_skip_read(stuffer, 1));
    }

    return 0;
}

/* Skips an expected character in the stuffer between min and max times */
int s2n_stuffer_skip_expected_char(struct s2n_stuffer *stuffer, const char expected, int min, int max)
{
    int skipped = 0;
    while (stuffer->read_cursor < stuffer->write_cursor && skipped < max) {
        if (stuffer->blob.data[stuffer->read_cursor] == expected){
            stuffer->read_cursor += 1;
            skipped += 1;
        } else {
            break;
        }
    }

    S2N_ERROR_IF(skipped < min, S2N_ERR_STUFFER_NOT_FOUND);

    return skipped;
}

/* Read a line of text. Agnostic to LF or CR+LF line endings. */
int s2n_stuffer_read_line(struct s2n_stuffer *stuffer, struct s2n_stuffer *token)
{
    /* Consume an LF terminated line */
    GUARD(s2n_stuffer_read_token(stuffer, token, '\n'));

    /* Snip off the carriage return if it's present */
    if ((s2n_stuffer_data_available(token) > 0) && (token->blob.data[(token->write_cursor - 1)] == '\r')) {
        token->write_cursor--;
    }

    return 0;
}

int s2n_stuffer_read_token(struct s2n_stuffer *stuffer, struct s2n_stuffer *token, char delim)
{
    int token_size = 0;

    while ((stuffer->read_cursor + token_size) < stuffer->write_cursor) {
        if (stuffer->blob.data[stuffer->read_cursor + token_size] == delim) {
            break;
        }

        token_size++;
    }

    GUARD(s2n_stuffer_copy(stuffer, token, token_size));

    /* Consume the delimiter too */
    if (stuffer->read_cursor < stuffer->write_cursor) {
        stuffer->read_cursor++;
    }

    return 0;
}

int s2n_stuffer_alloc_ro_from_string(struct s2n_stuffer *stuffer, const char *str)
{
    uint32_t length = strlen(str);

    GUARD(s2n_stuffer_alloc(stuffer, length + 1));
    return s2n_stuffer_write_bytes(stuffer, (const uint8_t *)str, length);
}
