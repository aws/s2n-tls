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

/**
 * This feature detects if the compiler properly pops diagnostics
 */

#include <stdint.h>

#define MACRO_CHECK \
    do { \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic error \"-Wconversion\"") \
        return -1; \
        _Pragma("GCC diagnostic pop") \
    } while (0)

int signed_fun()
{
    MACRO_CHECK;
}

/* This function is here to ensure the compiler properly pops the previous diagnostic.
 *
 * GCC 4 and lower don't correctly pop diagnostics so this will fail on those systems.
 **/
uint8_t unsigned_fun()
{
    return -1;
}

int main()
{
    signed_fun();
    unsigned_fun();

    MACRO_CHECK;
}
