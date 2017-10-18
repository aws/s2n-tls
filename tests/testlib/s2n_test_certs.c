/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdio.h>
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#include "testlib/s2n_testlib.h"

int s2n_read_test_pem(const char *pem_path, char *pem_out, long int max_size)
{
    long int file_length = 0;
    int ret_val = s2n_read_test_file(pem_path, pem_out, max_size, &file_length);
    pem_out[file_length] = '\0';

    return ret_val;
}

int s2n_read_test_file(const char *path, char *out, long int max_size, long int *file_size)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        S2N_ERROR(S2N_ERR_NULL);
    }

    // Make sure we can fit the pem into the output buffer
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    // one extra for the null byte
    rewind(file);

    if (max_size < (*file_size + 1)) {
        S2N_ERROR(S2N_ERR_NOMEM);
    }

    if (fread(out, sizeof(char), *file_size, file) < *file_size) {
        S2N_ERROR(S2N_ERR_IO);
    }

    fclose(file);

    return 0;
}
