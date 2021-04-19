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
#pragma once

#include <stdint.h>

extern char *s2n_strcpy(char *buf, char *last, const char *str);
int s2n_str_hex_to_bytes_length(const uint8_t *hex, uint32_t *out_bytes_len);
int s2n_str_hex_to_bytes(const uint8_t *hex, uint8_t *out_bytes, uint32_t *out_bytes_len);
