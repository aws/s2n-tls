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
    POSTCONDITION_POSIX(s2n_stuffer_validate(s2n_stuffer));
    return r;
}

/* Peeks in stuffer to see if expected string is present. */
int s2n_stuffer_peek_check_for_str(struct s2n_stuffer *s2n_stuffer, const char *expected)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(s2n_stuffer));
    uint32_t orig_read_pos = s2n_stuffer->read_cursor;
    int rc = s2n_stuffer_read_expected_str(s2n_stuffer, expected);
    s2n_stuffer->read_cursor = orig_read_pos;
    POSTCONDITION_POSIX(s2n_stuffer_validate(s2n_stuffer));
    return rc;
}

int s2n_stuffer_skip_whitespace(struct s2n_stuffer *s2n_stuffer, uint32_t *skipped)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(s2n_stuffer));
    uint32_t initial_read_cursor = s2n_stuffer->read_cursor;
    while (s2n_stuffer->read_cursor < s2n_stuffer->write_cursor) {
        switch (s2n_stuffer->blob.data[s2n_stuffer->read_cursor]) {
        case ' ':              /* We don't use isspace, because it changes under locales */
        case '\t':
        case '\n':
        case '\r':
            s2n_stuffer->read_cursor += 1;
            break;
        default:
            goto finished;
        }
    }
    finished:
    if(skipped != NULL) *skipped = s2n_stuffer->read_cursor - initial_read_cursor;
    POSTCONDITION_POSIX(s2n_stuffer_validate(s2n_stuffer));
    return S2N_SUCCESS;
}

int s2n_stuffer_read_expected_str(struct s2n_stuffer *stuffer, const char *expected)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    notnull_check(expected);
    size_t expected_length = strlen(expected);
    if (expected_length == 0) {
        return S2N_SUCCESS;
    }
    ENSURE_POSIX(s2n_stuffer_data_available(stuffer) >= expected_length, S2N_ERR_STUFFER_OUT_OF_DATA);
    uint8_t *actual = stuffer->blob.data + stuffer->read_cursor;
    notnull_check(actual);
    ENSURE_POSIX(!memcmp(actual, expected, expected_length), S2N_ERR_STUFFER_NOT_FOUND);
    stuffer->read_cursor += expected_length;
    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    return S2N_SUCCESS;
}

/* Read from stuffer until the target string is found, or until there is no more data. */
int s2n_stuffer_skip_read_until(struct s2n_stuffer *stuffer, const char *target)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    notnull_check(target);
    const int len = strlen(target);
    if (len == 0) {
        return S2N_SUCCESS;
    }
    while (s2n_stuffer_data_available(stuffer) >= len) {
        GUARD(s2n_stuffer_skip_to_char(stuffer, target[0]));
        GUARD(s2n_stuffer_skip_read(stuffer, len));
        uint8_t *actual = stuffer->blob.data + stuffer->read_cursor - len;
        notnull_check(actual);

        if (strncmp((char*)actual, target, len) == 0){
            return S2N_SUCCESS;
        } else {
            /* If string doesn't match, rewind stuffer to 1 byte after last read */
            GUARD(s2n_stuffer_rewind_read(stuffer, len - 1));
            continue;
        }
    }
    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    return S2N_SUCCESS;
}

/* Skips the stuffer until the first instance of the target character or until there is no more data. */
int s2n_stuffer_skip_to_char(struct s2n_stuffer *stuffer, const char target)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    while (s2n_stuffer_data_available(stuffer) > 0) {
        if (stuffer->blob.data[stuffer->read_cursor] == target) {
            break;
        }
        stuffer->read_cursor += 1;
    }
    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    return S2N_SUCCESS;
}

/* Skips an expected character in the stuffer between min and max times */
int s2n_stuffer_skip_expected_char(struct s2n_stuffer *stuffer, const char expected, const uint32_t min, const uint32_t max, uint32_t *skipped)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    ENSURE_POSIX(min <= max, S2N_ERR_SAFETY);

    uint32_t skip = 0;
    while (stuffer->read_cursor < stuffer->write_cursor && skip < max) {
        if (stuffer->blob.data[stuffer->read_cursor] == expected){
            stuffer->read_cursor += 1;
            skip += 1;
        } else {
            break;
        }
    }
    ENSURE_POSIX(skip >= min, S2N_ERR_STUFFER_NOT_FOUND);
    if(skipped != NULL) *skipped = skip;
    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    return S2N_SUCCESS;
}

/* Read a line of text. Agnostic to LF or CR+LF line endings. */
int s2n_stuffer_read_line(struct s2n_stuffer *stuffer, struct s2n_stuffer *token)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    PRECONDITION_POSIX(s2n_stuffer_validate(token));
    /* Consume an LF terminated line */
    GUARD(s2n_stuffer_read_token(stuffer, token, '\n'));

    /* Snip off the carriage return if it's present */
    if ((s2n_stuffer_data_available(token) > 0) && (token->blob.data[(token->write_cursor - 1)] == '\r')) {
        token->write_cursor--;
    }
    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    POSTCONDITION_POSIX(s2n_stuffer_validate(token));
    return S2N_SUCCESS;
}

int s2n_stuffer_read_token(struct s2n_stuffer *stuffer, struct s2n_stuffer *token, char delim)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    PRECONDITION_POSIX(s2n_stuffer_validate(token));
    uint32_t token_size = 0;

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

    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    POSTCONDITION_POSIX(s2n_stuffer_validate(token));
    return S2N_SUCCESS;
}

int s2n_stuffer_alloc_ro_from_string(struct s2n_stuffer *stuffer, const char *str)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    notnull_check(str);
    uint32_t length = strlen(str);
    GUARD(s2n_stuffer_alloc(stuffer, length + 1));
    return s2n_stuffer_write_bytes(stuffer, (const uint8_t *)str, length);
}
