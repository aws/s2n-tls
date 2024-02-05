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

#include <stdint.h>

/* make sure we can call `_Pragma` in macros */
#define MACRO_CHECK \
    do { \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic ignored \"-Wsign-conversion\"") \
        return -1; \
    } while (0)

uint8_t unsigned_fun()
{
    MACRO_CHECK;
}

int main()
{
    const int value = 0;
    const int *value_ptr = &value;

    unsigned_fun();

    /* make sure we can also push diagnostics via `#pragma` */
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
    int *value_ptr_mut = (int*)value_ptr;

    return *value_ptr_mut;
}
