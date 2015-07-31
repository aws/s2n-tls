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

#include <string.h>

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

int s2n_stuffer_peek_char(struct s2n_stuffer *s2n_stuffer, char *c)
{
    int r = s2n_stuffer_read_uint8(s2n_stuffer, (uint8_t *) c);
    if (r == 0) {
        s2n_stuffer->read_cursor--;
    }
    return r;
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
