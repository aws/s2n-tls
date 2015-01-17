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

#pragma once

#include <stdint.h>

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"

/* Read and write hex */
extern int s2n_stuffer_read_hex(struct s2n_stuffer *stuffer, struct s2n_stuffer *out, uint32_t n);
extern int s2n_stuffer_read_uint8_hex(struct s2n_stuffer *stuffer, uint8_t *u);
extern int s2n_stuffer_read_uint16_hex(struct s2n_stuffer *stuffer, uint16_t *u);
extern int s2n_stuffer_read_uint32_hex(struct s2n_stuffer *stuffer, uint32_t *u);
extern int s2n_stuffer_read_uint64_hex(struct s2n_stuffer *stuffer, uint64_t *u);

extern int s2n_stuffer_write_hex(struct s2n_stuffer *stuffer, struct s2n_stuffer *in, uint32_t n);
extern int s2n_stuffer_write_uint8_hex(struct s2n_stuffer *stuffer, uint8_t u);
extern int s2n_stuffer_write_uint16_hex(struct s2n_stuffer *stuffer, uint16_t u);
extern int s2n_stuffer_write_uint32_hex(struct s2n_stuffer *stuffer, uint32_t u);
extern int s2n_stuffer_write_uint64_hex(struct s2n_stuffer *stuffer, uint64_t u);
extern int s2n_stuffer_alloc_ro_from_hex_string(struct s2n_stuffer *stuffer, const char *str);

void s2n_print_connection(struct s2n_connection *conn, const char *marker);
