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

#include "api/s2n.h"

#include "stuffer/s2n_stuffer.h"

#include <assert.h>

void s2n_is_base64_char_harness() {
    unsigned char c;
    bool is_base_64 = ('A' <= c && c <= 'Z') ||
                      ('a' <= c && c <= 'z') ||
                      ('0' <= c && c <= '9') ||
                      c == '+' || c == '/' || c == '=';
    assert(is_base_64 == s2n_is_base64_char(c));
}
