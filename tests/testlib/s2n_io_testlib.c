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

#include "testlib/s2n_testlib.h"

S2N_CLEANUP_RESULT s2n_test_iovecs_free(struct s2n_test_iovecs *in)
{
    RESULT_ENSURE_REF(in);
    for (size_t i = 0; i < in->iovecs_count; i++) {
        RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &in->iovecs[i].iov_base,
                in->iovecs[i].iov_len));
    }
    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &in->iovecs,
            sizeof(struct iovec) * in->iovecs_count));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_split_data(struct s2n_test_iovecs *iovecs, struct s2n_blob *data)
{
    RESULT_ENSURE_REF(iovecs);
    RESULT_ENSURE_REF(data);

    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, data));

    for (size_t i = 0; i < iovecs->iovecs_count; i++) {
        if (iovecs->iovecs[i].iov_len == 0) {
            continue;
        }
        struct s2n_blob mem = { 0 };
        RESULT_GUARD_POSIX(s2n_alloc(&mem, iovecs->iovecs[i].iov_len));
        RESULT_GUARD_POSIX(s2n_stuffer_read(&in, &mem));
        iovecs->iovecs[i].iov_base = mem.data;
    }
    RESULT_ENSURE_EQ(s2n_stuffer_data_available(&in), 0);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_new_iovecs(struct s2n_test_iovecs *iovecs,
        struct s2n_blob *data, const size_t *lens, size_t lens_count)
{
    RESULT_ENSURE_REF(iovecs);
    RESULT_ENSURE_REF(data);
    RESULT_ENSURE_REF(lens);

    size_t len_total = 0;
    for (size_t i = 0; i < lens_count; i++) {
        len_total += lens[i];
    }
    RESULT_ENSURE_LTE(len_total, data->size);

    size_t iovecs_count = lens_count;
    if (len_total < data->size) {
        iovecs_count++;
    }

    struct s2n_blob iovecs_mem = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&iovecs_mem, sizeof(struct iovec) * iovecs_count));
    RESULT_GUARD_POSIX(s2n_blob_zero(&iovecs_mem));
    iovecs->iovecs = (struct iovec *) (void *) iovecs_mem.data;
    iovecs->iovecs_count = iovecs_count;

    for (size_t i = 0; i < lens_count; i++) {
        iovecs->iovecs[i].iov_len = lens[i];
    }
    if (lens_count < iovecs_count) {
        iovecs->iovecs[lens_count].iov_len = data->size - len_total;
    }

    RESULT_GUARD(s2n_test_split_data(iovecs, data));
    return S2N_RESULT_OK;
}
