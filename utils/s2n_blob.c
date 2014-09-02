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

#include "utils/s2n_blob.h"

int s2n_blob_init(struct s2n_blob *b, uint8_t *data, uint32_t size, const char **err)
{
    b->data = data;
    b->size = size;
    return 0;
}

int s2n_blob_zero(struct s2n_blob *b, const char **err)
{
    if (memset(b->data, 0, b->size) != b->data) {
        *err = "Could not zero a blob";
        return -1;
    }

    return 0;
}
