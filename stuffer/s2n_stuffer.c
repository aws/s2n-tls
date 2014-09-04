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
#include <unistd.h>
#include <errno.h>

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

int s2n_stuffer_init(struct s2n_stuffer *stuffer, struct s2n_blob *in, const char **err)
{
    stuffer->blob.data = in->data;
    stuffer->blob.size = in->size;
    stuffer->wiped = 1;
    stuffer->alloced = 0;
    stuffer->growable = 0;
    stuffer->tainted = 0;
    stuffer->read_cursor = 0;
    stuffer->write_cursor = 0;

    return 0;
}

int s2n_stuffer_alloc(struct s2n_stuffer *stuffer, uint32_t size, const char **err)
{
    if (s2n_alloc(&stuffer->blob, size, err) < 0) {
        return -1;
    }
    if (s2n_stuffer_init(stuffer, &stuffer->blob, err) < 0) {
        return -1;
    }
    stuffer->alloced = 1;

    return 0;
}

int s2n_stuffer_growable_alloc(struct s2n_stuffer *stuffer, uint32_t size, const char **err)
{
    if (s2n_stuffer_alloc(stuffer, size, err) < 0) {
        return -1;
    }
    stuffer->growable = 1;

    return 0;
}

int s2n_stuffer_free(struct s2n_stuffer *stuffer, const char **err)
{
    if (stuffer->alloced == 0) {
        return 0;
    }
    if (stuffer->wiped == 0) {
        if (s2n_stuffer_wipe(stuffer, err) < 0) {
            return -1;
        }
    }
    if (s2n_free(&stuffer->blob, err) < 0) {
        return -1;
    }
    stuffer->blob.data = NULL;
    stuffer->blob.size = 0;

    return 0;
}

int s2n_stuffer_resize(struct s2n_stuffer *stuffer, uint32_t size, const char **err)
{
    if (stuffer->growable == 0) {
        *err = "Cannot resize a static stuffer";
        return -1;
    }
    if (stuffer->tainted == 1) {
        *err = "Cannot resize a stuffer while tainted";
        return -1;
    }
    if (size == stuffer->blob.size) {
        return 0;
    }
    if (size < stuffer->blob.size) {
        if (s2n_stuffer_wipe_n(stuffer, stuffer->blob.size - size, err) < 0) {
            return -1;
        }
    }
    if (s2n_realloc(&stuffer->blob, size, err) < 0) {
        return -1;
    }
    stuffer->blob.size = size;

    return 0;
}

int s2n_stuffer_rewrite(struct s2n_stuffer *stuffer, const char **err)
{
    stuffer->write_cursor = 0;
    if (stuffer->read_cursor > stuffer->write_cursor) {
        stuffer->read_cursor = stuffer->write_cursor;
    }
    return 0;
}

int s2n_stuffer_reread(struct s2n_stuffer *stuffer, const char **err)
{
    stuffer->read_cursor = 0;
    return 0;
}

int s2n_stuffer_wipe_n(struct s2n_stuffer *stuffer, uint32_t n, const char **err)
{
    if (stuffer->write_cursor < n) {
        n = stuffer->write_cursor;
    }

    /* Use '0' instead of 0 precisely to prevent C string compatibility */
    if (memset(stuffer->blob.data + stuffer->write_cursor - n, '0', n) != stuffer->blob.data + stuffer->write_cursor - n) {
        *err = "Error calling memset()";
        return -1;
    }
    stuffer->write_cursor -= n;

    if (stuffer->write_cursor == 0) {
        stuffer->wiped = 1;
    }
    if (stuffer->write_cursor < stuffer->read_cursor) {
        stuffer->read_cursor = stuffer->write_cursor;
    }

    return 0;
}

int s2n_stuffer_wipe(struct s2n_stuffer *stuffer, const char **err)
{
    stuffer->tainted = 0;
    return s2n_stuffer_wipe_n(stuffer, stuffer->write_cursor, err);
}

int s2n_stuffer_skip_read(struct s2n_stuffer *stuffer, uint32_t n, const char **err)
{
    if (s2n_stuffer_data_available(stuffer) < n) {
        *err = "stuffer out of data to read";
        return -1;
    }

    stuffer->read_cursor += n;
    return 0;
}

void *s2n_stuffer_raw_read(struct s2n_stuffer *stuffer, uint32_t data_len, const char **err)
{
    if (s2n_stuffer_skip_read(stuffer, data_len, err) < 0) {
        return NULL;
    }

    stuffer->tainted = 1;

    return stuffer->blob.data + stuffer->read_cursor - data_len;
}

int s2n_stuffer_read(struct s2n_stuffer *stuffer, struct s2n_blob *out, const char **err)
{
    if (s2n_stuffer_skip_read(stuffer, out->size, err) < 0) {
        return -1;
    }

    void *ptr = stuffer->blob.data + stuffer->read_cursor - out->size;
    if (ptr == NULL) {
        return -1;
    }

    memcpy_check(out->data, ptr, out->size);

    return 0;
}

int s2n_stuffer_erase_and_read(struct s2n_stuffer *stuffer, struct s2n_blob *out, const char **err)
{
    if (s2n_stuffer_skip_read(stuffer, out->size, err) < 0) {
        return -1;
    }

    void *ptr = stuffer->blob.data + stuffer->read_cursor - out->size;
    if (ptr == NULL) {
        return -1;
    }

    memcpy_check(out->data, ptr, out->size);
    memset(ptr, 0, out->size);

    return 0;
}

int s2n_stuffer_read_bytes(struct s2n_stuffer *stuffer, uint8_t *bytes, uint32_t n, const char **err)
{
    struct s2n_blob out = {.data = bytes,.size = n };

    return s2n_stuffer_read(stuffer, &out, err);
}

int s2n_stuffer_skip_write(struct s2n_stuffer *stuffer, uint32_t n, const char **err)
{
    if (s2n_stuffer_space_remaining(stuffer) < n) {
        if (stuffer->growable) {
            /* Always grow a stuffer by at least 1k */
            uint32_t growth = n;
            if (growth < 1024) {
                growth = 1024;
            }
            if (s2n_stuffer_resize(stuffer, stuffer->blob.size + growth, err) < 0) {
                return -1;
            }
        } else {
            *err = "Not enough space left in stuffer for write";
            return -1;
        }
    }

    stuffer->write_cursor += n;
    stuffer->wiped = 0;
    return 0;
}

void *s2n_stuffer_raw_write(struct s2n_stuffer *stuffer, uint32_t data_len, const char **err)
{
    if (s2n_stuffer_skip_write(stuffer, data_len, err) < 0) {
        return NULL;
    }

    stuffer->tainted = 1;

    return stuffer->blob.data + stuffer->write_cursor - data_len;
}

int s2n_stuffer_write(struct s2n_stuffer *stuffer, struct s2n_blob *in, const char **err)
{
    if (s2n_stuffer_skip_write(stuffer, in->size, err) < 0) {
        return -1;
    }

    void *ptr = stuffer->blob.data + stuffer->write_cursor - in->size;
    if (ptr == NULL) {
        return -1;
    }

    memcpy_check(ptr, in->data, in->size);

    return 0;
}

int s2n_stuffer_write_bytes(struct s2n_stuffer *stuffer, uint8_t *bytes, uint32_t n, const char **err)
{
    struct s2n_blob in = {.data = bytes,.size = n };

    return s2n_stuffer_write(stuffer, &in, err);
}

int s2n_stuffer_read_uint8(struct s2n_stuffer *stuffer, uint8_t *u, const char **err)
{
    struct s2n_blob b = {.data = u,.size = 1 };
    if (s2n_stuffer_read(stuffer, &b, err) < 0) {
        return -1;
    }

    return 0;
}

int s2n_stuffer_write_uint8(struct s2n_stuffer *stuffer, uint8_t u, const char **err)
{
    struct s2n_blob b = {.data = &u,.size = 1 };
    if (s2n_stuffer_write(stuffer, &b, err) < 0) {
        return -1;
    }

    return 0;
}

int s2n_stuffer_read_uint16(struct s2n_stuffer *stuffer, uint16_t *u, const char **err)
{
    uint8_t data[2];
    struct s2n_blob b = {.data = data,.size = sizeof(data) };
    if (s2n_stuffer_read(stuffer, &b, err) < 0) {
        return -1;
    }

    *u = data[0] << 8;
    *u |= data[1];

    return 0;
}

int s2n_stuffer_write_uint16(struct s2n_stuffer *stuffer, uint16_t u, const char **err)
{
    uint8_t data[2] = { u >> 8, u & 0xff };
    struct s2n_blob b = {.data = data,.size = sizeof(data) };

    if (s2n_stuffer_write(stuffer, &b, err) < 0) {
        return -1;
    }

    return 0;
}

int s2n_stuffer_read_uint24(struct s2n_stuffer *stuffer, uint32_t *u, const char **err)
{
    uint8_t data[3];
    struct s2n_blob b = {.data = data,.size = sizeof(data) };
    if (s2n_stuffer_read(stuffer, &b, err) < 0) {
        return -1;
    }

    *u = data[0] << 16;
    *u |= data[1] << 8;
    *u |= data[2];

    return 0;
}

int s2n_stuffer_write_uint24(struct s2n_stuffer *stuffer, uint32_t u, const char **err)
{
    uint8_t data[3] = { u >> 16, u >> 8, u & 0xff };
    struct s2n_blob b = {.data = data,.size = sizeof(data) };

    if (s2n_stuffer_write(stuffer, &b, err) < 0) {
        return -1;
    }

    return 0;
}

int s2n_stuffer_read_uint32(struct s2n_stuffer *stuffer, uint32_t *u, const char **err)
{
    uint8_t data[4];
    struct s2n_blob b = {.data = data,.size = sizeof(data) };
    if (s2n_stuffer_read(stuffer, &b, err) < 0) {
        return -1;
    }

    *u = data[0] << 24;
    *u |= data[1] << 16;
    *u |= data[2] << 8;
    *u |= data[3];

    return 0;
}

int s2n_stuffer_write_uint32(struct s2n_stuffer *stuffer, uint32_t u, const char **err)
{
    uint8_t data[4] = { u >> 24, u >> 16, u >> 8, u & 0xff };
    struct s2n_blob b = {.data = data,.size = sizeof(data) };

    if (s2n_stuffer_write(stuffer, &b, err) < 0) {
        return -1;
    }

    return 0;
}

int s2n_stuffer_copy(struct s2n_stuffer *from, struct s2n_stuffer *to, uint32_t len, const char **err)
{
    if (s2n_stuffer_skip_read(from, len, err) < 0) {
        return -1;
    }

    if (s2n_stuffer_skip_write(to, len, err) < 0) {
        return -1;
    }

    uint8_t *from_ptr = from->blob.data + from->read_cursor - len;
    uint8_t *to_ptr = to->blob.data + to->write_cursor - len;

    memcpy_check(to_ptr, from_ptr, len);

    return 0;
}
