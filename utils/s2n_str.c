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
#include <sys/param.h>
#include "utils/s2n_str.h"

char *s2n_strcpy(char *buf, char *last, const char *str) {

/* CBMC pointer checks need to be disabled to compare buf and last for
 * the case where they are the same. */
#pragma CPROVER check push
#pragma CPROVER check disable "pointer"

    if (buf >= last) {
        return buf;
    }

#pragma CPROVER check pop

    if (NULL == str) {
        *buf = '\0';
        return buf;
    }

    /* Free bytes needs to be one byte smaller than size of a storage, 
     * as strncpy always writes '\0', but doesn't include it in n 
     */
    size_t bytes_to_copy = MIN(last - buf - 1, strlen(str));

    char *p = buf;
    if (bytes_to_copy > 0) {
        p = (char *)memcpy(buf, str, bytes_to_copy) + bytes_to_copy;
    }
    *p = '\0';

    return p;
}
