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

#include <sys/param.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

int s2n_stuffer_init(struct s2n_stuffer *stuffer, struct s2n_blob *in)
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

int s2n_stuffer_alloc(struct s2n_stuffer *stuffer, const uint32_t size)
{

    GUARD(s2n_alloc(&stuffer->blob, size));
    GUARD(s2n_stuffer_init(stuffer, &stuffer->blob));

    stuffer->alloced = 1;

    return 0;
}

int s2n_stuffer_growable_alloc(struct s2n_stuffer *stuffer, const uint32_t size)
{
    GUARD(s2n_stuffer_alloc(stuffer, size));

    stuffer->growable = 1;

    return 0;
}

int s2n_stuffer_free(struct s2n_stuffer *stuffer)
{
    if (stuffer->alloced == 0) {
        return 0;
    }
    if (stuffer->wiped == 0) {
        GUARD(s2n_stuffer_wipe(stuffer));
    }

    GUARD(s2n_free(&stuffer->blob));

    stuffer->blob.data = NULL;
    stuffer->blob.size = 0;

    return 0;
}

int s2n_stuffer_resize(struct s2n_stuffer *stuffer, const uint32_t size)
{
    if (stuffer->growable == 0) {
        S2N_ERROR(S2N_ERR_RESIZE_STATIC_STUFFER);
    }
    if (stuffer->tainted == 1) {
        S2N_ERROR(S2N_ERR_RESIZE_TAINTED_STUFFER);
    }
    if (size == stuffer->blob.size) {
        return 0;
    }
    if (size < stuffer->blob.size) {
        GUARD(s2n_stuffer_wipe_n(stuffer, stuffer->blob.size - size));
    }

    GUARD(s2n_realloc(&stuffer->blob, size));

    stuffer->blob.size = size;

    return 0;
}

int s2n_stuffer_rewrite(struct s2n_stuffer *stuffer)
{
    stuffer->write_cursor = 0;
    stuffer->read_cursor = 0;

    return 0;
}

int s2n_stuffer_reread(struct s2n_stuffer *stuffer)
{
    stuffer->read_cursor = 0;
    return 0;
}

int s2n_stuffer_wipe_n(struct s2n_stuffer *stuffer, const uint32_t size)
{
    uint32_t n = MIN(size, stuffer->write_cursor);

    /* Use '0' instead of 0 precisely to prevent C string compatibility */
    memset_check(stuffer->blob.data + stuffer->write_cursor - n, '0', n);
    stuffer->write_cursor -= n;

    if (stuffer->write_cursor == 0) {
        stuffer->wiped = 1;
    }

    stuffer->read_cursor = MIN(stuffer->read_cursor, stuffer->write_cursor);

    return 0;
}

int s2n_stuffer_wipe(struct s2n_stuffer *stuffer)
{
    stuffer->tainted = 0;
    return s2n_stuffer_wipe_n(stuffer, stuffer->write_cursor);
}

int s2n_stuffer_skip_read(struct s2n_stuffer *stuffer, uint32_t n)
{
    if (s2n_stuffer_data_available(stuffer) < n) {
        S2N_ERROR(S2N_ERR_STUFFER_OUT_OF_DATA);
    }

    stuffer->read_cursor += n;
    return 0;
}

void *s2n_stuffer_raw_read(struct s2n_stuffer *stuffer, uint32_t data_len)
{
    GUARD_PTR(s2n_stuffer_skip_read(stuffer, data_len));

    stuffer->tainted = 1;

    return stuffer->blob.data + stuffer->read_cursor - data_len;
}

int s2n_stuffer_read(struct s2n_stuffer *stuffer, struct s2n_blob *out)
{
    notnull_check(out);

    return s2n_stuffer_read_bytes(stuffer, out->data, out->size);
}

int s2n_stuffer_erase_and_read(struct s2n_stuffer *stuffer, struct s2n_blob *out)
{
    GUARD(s2n_stuffer_skip_read(stuffer, out->size));

    void *ptr = stuffer->blob.data + stuffer->read_cursor - out->size;
    if (ptr == NULL) {
        return -1;
    }

    memcpy_check(out->data, ptr, out->size);
    memset(ptr, 0, out->size);

    return 0;
}

int s2n_stuffer_read_bytes(struct s2n_stuffer *stuffer, uint8_t * data, uint32_t size)
{
    GUARD(s2n_stuffer_skip_read(stuffer, size));

    void *ptr = stuffer->blob.data + stuffer->read_cursor - size;
    notnull_check(ptr);

    memcpy_check(data, ptr, size);

    return 0;
}

int s2n_stuffer_skip_write(struct s2n_stuffer *stuffer, const uint32_t n)
{
    if (s2n_stuffer_space_remaining(stuffer) < n) {
        if (stuffer->growable) {
            /* Always grow a stuffer by at least 1k */
            uint32_t growth = MAX(n, 1024);

            GUARD(s2n_stuffer_resize(stuffer, stuffer->blob.size + growth));
        } else {
            S2N_ERROR(S2N_ERR_STUFFER_IS_FULL);
        }
    }

    stuffer->write_cursor += n;
    stuffer->wiped = 0;
    return 0;
}

void *s2n_stuffer_raw_write(struct s2n_stuffer *stuffer, const uint32_t data_len)
{
    GUARD_PTR(s2n_stuffer_skip_write(stuffer, data_len));

    stuffer->tainted = 1;

    return stuffer->blob.data + stuffer->write_cursor - data_len;
}

int s2n_stuffer_write(struct s2n_stuffer *stuffer, const struct s2n_blob *in)
{
    return s2n_stuffer_write_bytes(stuffer, in->data, in->size);
}

int s2n_stuffer_write_bytes(struct s2n_stuffer *stuffer, const uint8_t * data, const uint32_t size)
{
    GUARD(s2n_stuffer_skip_write(stuffer, size));

    void *ptr = stuffer->blob.data + stuffer->write_cursor - size;
    if (ptr == NULL) {
        return -1;
    }

    if (ptr == data) {
        return 0;
    }

    memcpy_check(ptr, data, size);

    return 0;
}

int s2n_stuffer_read_uint8(struct s2n_stuffer *stuffer, uint8_t * u)
{
    GUARD(s2n_stuffer_read_bytes(stuffer, u, 1));

    return 0;
}

int s2n_stuffer_write_uint8(struct s2n_stuffer *stuffer, const uint8_t u)
{
    GUARD(s2n_stuffer_write_bytes(stuffer, &u, 1));

    return 0;
}

int s2n_stuffer_read_uint16(struct s2n_stuffer *stuffer, uint16_t * u)
{
    uint8_t data[2];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = data[0] << 8;
    *u |= data[1];

    return 0;
}

int s2n_stuffer_write_uint16(struct s2n_stuffer *stuffer, const uint16_t u)
{
    uint8_t data[2] = { u >> 8, u & 0xff };

    GUARD(s2n_stuffer_write_bytes(stuffer, data, sizeof(data)));

    return 0;
}

int s2n_stuffer_read_uint24(struct s2n_stuffer *stuffer, uint32_t * u)
{
    uint8_t data[3];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = data[0] << 16;
    *u |= data[1] << 8;
    *u |= data[2];

    return 0;
}

int s2n_stuffer_write_uint24(struct s2n_stuffer *stuffer, const uint32_t u)
{
    uint8_t data[3] = { u >> 16, u >> 8, u & 0xff };

    GUARD(s2n_stuffer_write_bytes(stuffer, data, sizeof(data)));

    return 0;
}

int s2n_stuffer_read_uint32(struct s2n_stuffer *stuffer, uint32_t * u)
{
    uint8_t data[4];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = ((uint32_t) data[0]) << 24;
    *u |= data[1] << 16;
    *u |= data[2] << 8;
    *u |= data[3];

    return 0;
}

int s2n_stuffer_write_uint32(struct s2n_stuffer *stuffer, const uint32_t u)
{
    uint8_t data[4] = { u >> 24, u >> 16, u >> 8, u & 0xff };

    GUARD(s2n_stuffer_write_bytes(stuffer, data, sizeof(data)));

    return 0;
}

int s2n_stuffer_read_uint64(struct s2n_stuffer *stuffer, uint64_t * u)
{
    uint8_t data[8];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = ((uint64_t) data[0]) << 56;
    *u |= ((uint64_t) data[1]) << 48;
    *u |= ((uint64_t) data[2]) << 40;
    *u |= ((uint64_t) data[3]) << 32;
    *u |= ((uint64_t) data[4]) << 24;
    *u |= ((uint64_t) data[5]) << 16;
    *u |= ((uint64_t) data[6]) << 8;
    *u |= data[7];

    return 0;
}

int s2n_stuffer_write_uint64(struct s2n_stuffer *stuffer, const uint64_t u)
{
    uint8_t data[8] = { u >> 56, u >> 48, u >> 40, u >> 32, u >> 24, u >> 16, u >> 8, u & 0xff };

    GUARD(s2n_stuffer_write_bytes(stuffer, data, sizeof(data)));

    return 0;
}

int s2n_stuffer_copy(struct s2n_stuffer *from, struct s2n_stuffer *to, const uint32_t len)
{
    GUARD(s2n_stuffer_skip_read(from, len));

    GUARD(s2n_stuffer_skip_write(to, len));

    uint8_t *from_ptr = from->blob.data + from->read_cursor - len;
    uint8_t *to_ptr = to->blob.data + to->write_cursor - len;

    memcpy_check(to_ptr, from_ptr, len);

    return 0;
}
