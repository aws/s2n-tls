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

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#include "testlib/s2n_testlib.h"

static uint8_t hex[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/**
 * Helper function: read n bits of hex data.
 */
static int s2n_stuffer_read_n_bits_hex(struct s2n_stuffer *stuffer, uint8_t n, uint64_t *u, const char **err)
{
    uint8_t hex_data[16];
    struct s2n_blob b = { .data = hex_data, .size = n / 4 };

    if (s2n_stuffer_read(stuffer, &b, err) < 0) {
        return -1;
    }

    /* Start with u = 0 */
    *u = 0;

    for (int i = 0; i < b.size; i++) {
        *u <<= 4;
        if (b.data[i] >= '0' && b.data[i] <= '9') {
            *u |= b.data[i] - '0';
        } else if (b.data[i] >= 'a' && b.data[i] <= 'f') {
            *u |= b.data[i] - 'a' + 10;
        } else if (b.data[i] >= 'A' && b.data[i] <= 'F') {
            *u |= b.data[i] - 'A' + 10;
        } else {
            *err = "Non hex value encountered in hex reading";
            return -1;
        }
    }

    return 0;
}

int s2n_stuffer_read_hex(struct s2n_stuffer *stuffer, struct s2n_stuffer *out, uint32_t n, const char **err)
{
    gte_check(s2n_stuffer_space_remaining(out), n);

    for (int i = 0; i < n; i++) {
        uint8_t c;
        if (s2n_stuffer_read_uint8_hex(stuffer, &c, err) < 0) {
            return -1;
        }
        if (s2n_stuffer_write_uint8(out, c, err) < 0) {
            return -1;
        }
    }

    return 0;
}

int s2n_stuffer_write_hex(struct s2n_stuffer *stuffer, struct s2n_stuffer *in, uint32_t n, const char **err)
{
    gte_check(s2n_stuffer_space_remaining(stuffer), n * 2);

    for (int i = 0; i < n; i++) {
        uint8_t c;
        if (s2n_stuffer_read_uint8(in, &c, err) < 0) {
            return -1;
        }
        if (s2n_stuffer_write_uint8_hex(stuffer, c, err) < 0) {
            return -1;
        }
    }

    return 0;
}

int s2n_stuffer_read_uint64_hex(struct s2n_stuffer *stuffer, uint64_t *u, const char **err)
{
    return s2n_stuffer_read_n_bits_hex(stuffer, 64, u, err);
}

int s2n_stuffer_read_uint32_hex(struct s2n_stuffer *stuffer, uint32_t *u, const char **err)
{
    uint64_t u64;
    if (s2n_stuffer_read_n_bits_hex(stuffer, 32, &u64, err) < 0) {
        return -1;
    }

    *u = u64 & 0xffffffff;

    return 0;
}

int s2n_stuffer_read_uint16_hex(struct s2n_stuffer *stuffer, uint16_t *u, const char **err)
{
    uint64_t u64;
    if (s2n_stuffer_read_n_bits_hex(stuffer, 16, &u64, err) < 0) {
        return -1;
    }

    *u = u64 & 0xffff;

    return 0;
}

int s2n_stuffer_read_uint8_hex(struct s2n_stuffer *stuffer, uint8_t *u, const char **err)
{
    uint64_t u64;
    if (s2n_stuffer_read_n_bits_hex(stuffer, 8, &u64, err) < 0) {
        return -1;
    }

    *u = u64 & 0xff;

    return 0;
}

/**
 * Private helper: write n (up to 64) bits of hex data
 */
static int s2n_stuffer_write_n_bits_hex(struct s2n_stuffer *stuffer, uint8_t n, uint64_t u, const char **err)
{
    uint8_t hex_data[16] = { 0 };
    struct s2n_blob b = { .data = hex_data, .size = n / 4 };

    lte_check(n, 64);

    for (int i = b.size; i > 0; i--) {
        b.data[i - 1] = hex[u & 0x0f];
        u >>= 4;
    }

    if (s2n_stuffer_write(stuffer, &b, err) < 0) {
        return -1;
    }

    return 0;
}

int s2n_stuffer_write_uint64_hex(struct s2n_stuffer *stuffer, uint64_t u, const char **err)
{
    return s2n_stuffer_write_n_bits_hex(stuffer, 64, u, err);
}

int s2n_stuffer_write_uint32_hex(struct s2n_stuffer *stuffer, uint32_t u, const char **err)
{
    return s2n_stuffer_write_n_bits_hex(stuffer, 32, u, err);
}

int s2n_stuffer_write_uint16_hex(struct s2n_stuffer *stuffer, uint16_t u, const char **err)
{
    return s2n_stuffer_write_n_bits_hex(stuffer, 16, u, err);
}

int s2n_stuffer_write_uint8_hex(struct s2n_stuffer *stuffer, uint8_t u, const char **err)
{
    return s2n_stuffer_write_n_bits_hex(stuffer, 8, u, err);
}

int s2n_stuffer_alloc_ro_from_hex_string(struct s2n_stuffer *stuffer, const char *str, const char **err)
{
    if (strlen(str) % 2) {
        *err = "Hex strings must be even in length";
        return -1;
    }

    if (s2n_stuffer_alloc(stuffer, strlen(str) / 2, err) < 0) {
        return -1;
    }

    for (int i = 0; i < strlen(str); i++) {
        if (s2n_stuffer_write_uint8_hex(stuffer, str[i], err) < 0) {
            return -1;
        }
    }

    return 0;
}
