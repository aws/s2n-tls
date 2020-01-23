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

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

/* Using a non-zero value 
 * (a) makes wiped data easy to see in the debugger
 * (b) makes use of wiped data obvious since this is unlikely to be a valid bit pattern
 */
#define S2N_WIPE_PATTERN 'w'

bool s2n_stuffer_is_valid(const struct s2n_stuffer* stuffer)
{
    /* Note that we do not assert any properties on the alloced, growable, and tainted fields,
     * as all possible combinations of boolean values in those fields are valid */
    return S2N_OBJECT_PTR_IS_READABLE(stuffer) && 
        s2n_blob_is_valid(&stuffer->blob) &&
        /* <= is valid because we can have a fully written/read stuffer */
        stuffer->high_water_mark <= stuffer->blob.size &&
        stuffer->write_cursor <= stuffer->high_water_mark &&
        stuffer->read_cursor <= stuffer->write_cursor;
}

int s2n_stuffer_init(struct s2n_stuffer *stuffer, struct s2n_blob *in)
{
    S2N_PRECONDITION(S2N_OBJECT_PTR_IS_WRITABLE(stuffer));
    S2N_PRECONDITION(s2n_blob_is_valid(in));
    stuffer->blob = *in;
    stuffer->read_cursor = 0;
    stuffer->write_cursor = 0;
    stuffer->high_water_mark = 0;
    stuffer->alloced = 0;
    stuffer->growable = 0;
    stuffer->tainted = 0;
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
    if (stuffer->alloced) {
        GUARD(s2n_free(&stuffer->blob));
    }
    *stuffer = (struct s2n_stuffer) {0};

    return 0;
}

int s2n_stuffer_resize(struct s2n_stuffer *stuffer, const uint32_t size)
{
    S2N_ERROR_IF(stuffer->tainted == 1, S2N_ERR_RESIZE_TAINTED_STUFFER);
    S2N_ERROR_IF(stuffer->growable == 0, S2N_ERR_RESIZE_STATIC_STUFFER);

    if (size == stuffer->blob.size) {
        return 0;
    }

    if (size < stuffer->blob.size) {
        GUARD(s2n_stuffer_wipe_n(stuffer, stuffer->blob.size - size));
    }

    GUARD(s2n_realloc(&stuffer->blob, size));

    return 0;
}

int s2n_stuffer_resize_if_empty(struct s2n_stuffer *stuffer, const uint32_t size)
{
    if (stuffer->blob.data == NULL) {
        GUARD(s2n_stuffer_resize(stuffer, size));
    }

    return 0;
}

int s2n_stuffer_rewrite(struct s2n_stuffer *stuffer)
{
    stuffer->write_cursor = 0;
    stuffer->read_cursor = 0;

    return 0;
}

int s2n_stuffer_rewind_read(struct s2n_stuffer *stuffer, const uint32_t size)
{
    if(stuffer->read_cursor < size){
        S2N_ERROR(S2N_ERR_STUFFER_OUT_OF_DATA);
    }
    stuffer->read_cursor -= size;
    return 0;
}

int s2n_stuffer_reread(struct s2n_stuffer *stuffer)
{
    S2N_PRECONDITION(s2n_stuffer_is_valid(stuffer));
    stuffer->read_cursor = 0;
    return 0;
}

int s2n_stuffer_wipe_n(struct s2n_stuffer *stuffer, const uint32_t size)
{
    if (size >= stuffer->write_cursor) {
        return s2n_stuffer_wipe(stuffer);
    }

    /* We know that size is now less than write_cursor */
    stuffer->write_cursor -= size;
    memset_check(stuffer->blob.data + stuffer->write_cursor, S2N_WIPE_PATTERN, size);
    stuffer->read_cursor = MIN(stuffer->read_cursor, stuffer->write_cursor);
    
    return 0;
}

int s2n_stuffer_release_if_empty(struct s2n_stuffer *stuffer)
{
    if (stuffer->blob.data == NULL) {
        return 0;
    }

    S2N_ERROR_IF(stuffer->read_cursor != stuffer->write_cursor,
            S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA);

    GUARD(s2n_stuffer_wipe(stuffer));
    GUARD(s2n_stuffer_resize(stuffer, 0));

    return 0;
}

int s2n_stuffer_wipe(struct s2n_stuffer *stuffer)
{
    if (!s2n_stuffer_is_wiped(stuffer)) {
        memset_check(stuffer->blob.data, S2N_WIPE_PATTERN, stuffer->high_water_mark);
    }

    stuffer->tainted = 0;
    stuffer->write_cursor = 0;
    stuffer->read_cursor = 0;
    stuffer->high_water_mark = 0;
    return S2N_SUCCESS;
}

int s2n_stuffer_skip_read(struct s2n_stuffer *stuffer, uint32_t n)
{
    S2N_PRECONDITION(s2n_stuffer_is_valid(stuffer));
    S2N_ERROR_IF(s2n_stuffer_data_available(stuffer) < n, S2N_ERR_STUFFER_OUT_OF_DATA);

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
    notnull_check(ptr);

    memcpy_check(out->data, ptr, out->size);
    memset(ptr, 0, out->size);

    return 0;
}

int s2n_stuffer_read_bytes(struct s2n_stuffer *stuffer, uint8_t * data, uint32_t size)
{
    notnull_check(data);
    GUARD(s2n_stuffer_skip_read(stuffer, size));

    void *ptr = stuffer->blob.data + stuffer->read_cursor - size;
    notnull_check(ptr);

    memcpy_check(data, ptr, size);

    return 0;
}

int s2n_stuffer_erase_and_read_bytes(struct s2n_stuffer *stuffer, uint8_t * data, uint32_t size)
{
    GUARD(s2n_stuffer_skip_read(stuffer, size));

    void *ptr = stuffer->blob.data + stuffer->read_cursor - size;
    notnull_check(ptr);

    memcpy_check(data, ptr, size);
    memset(ptr, 0, size);

    return 0;
}

int s2n_stuffer_skip_write(struct s2n_stuffer *stuffer, const uint32_t n)
{
    if (s2n_stuffer_space_remaining(stuffer) < n) {
        if (stuffer->growable) {
            /* Always grow a stuffer by at least 1k */
            uint32_t growth = MAX(n - s2n_stuffer_space_remaining(stuffer), 1024);

            GUARD(s2n_stuffer_resize(stuffer, stuffer->blob.size + growth));
        } else {
            S2N_ERROR(S2N_ERR_STUFFER_IS_FULL);
        }
    }

    stuffer->write_cursor += n;
    stuffer->high_water_mark = MAX(stuffer->write_cursor, stuffer->high_water_mark);
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
    notnull_check(ptr);

    if (ptr == data) {
        return 0;
    }

    memcpy_check(ptr, data, size);

    return 0;
}

int s2n_stuffer_writev_bytes(struct s2n_stuffer *stuffer, const struct iovec* iov, int iov_count, size_t offs, size_t size)
{
    void *ptr = s2n_stuffer_raw_write(stuffer, size);
    notnull_check(ptr);

    size_t size_left = size, to_skip = offs;
    for (int i = 0; i < iov_count; i++) {
        if (to_skip >= iov[i].iov_len) {
            to_skip -= iov[i].iov_len;
            continue;
        }

        uint32_t iov_len = iov[i].iov_len - to_skip;
        uint32_t iov_size_to_take = MIN(size_left, iov_len);
        memcpy_check(ptr, (uint8_t*)iov[i].iov_base + to_skip, iov_size_to_take);
        size_left -= iov_size_to_take;
        if (size_left == 0) {
            break;
        }
        ptr = (void*)((uint8_t*)ptr + iov_size_to_take);
        to_skip = 0;
    }

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

int s2n_stuffer_extract_blob(struct s2n_stuffer *stuffer, struct s2n_blob *out)
{
    S2N_PRECONDITION(s2n_stuffer_is_valid(stuffer));
    notnull_check(out);
    GUARD(s2n_free(out));
    GUARD(s2n_alloc(out, s2n_stuffer_data_available(stuffer)));

    if (s2n_stuffer_data_available(stuffer) > 0) {
        memcpy_check(out->data,
                     stuffer->blob.data + stuffer->read_cursor,
                     s2n_stuffer_data_available(stuffer));
    }
    return S2N_SUCCESS;
}
