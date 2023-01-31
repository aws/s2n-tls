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

#define MACRO_CHECK \
    do { \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic error \"-Wconversion\"") \
        return -1; \
        _Pragma("GCC diagnostic pop") \
    } while (0)

int main()
{
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
    #pragma GCC diagnostic pop

    MACRO_CHECK;
}
