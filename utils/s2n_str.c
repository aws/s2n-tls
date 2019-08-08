/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "s2n_str.h"
#include <string.h>
#include <sys/param.h>

char *s2n_strcpy(char *buf, char *last, const char *str) {
    if (NULL == str || *str == '\0') {
        return buf;
    }

    /* free_bytes needs to be one byte smaller than size of a storage, as strncpy always writes \0, but doesn't include it in n */
    if (buf + 1 >= last) {
        return buf;
    }

    size_t bytes_to_copy = MIN(last - buf - 1, strlen(str));

    return strncpy(buf, str, bytes_to_copy) + bytes_to_copy;
}
