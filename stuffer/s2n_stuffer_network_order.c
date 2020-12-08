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

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_annotations.h"
#include "utils/s2n_safety.h"

/* Writes length bytes of input to stuffer, in network order, starting from the smallest byte of input. */
int s2n_stuffer_write_network_order(struct s2n_stuffer *stuffer, const uint64_t input, const uint8_t length)
{
    ENSURE_POSIX(length <= sizeof(input), S2N_ERR_SAFETY);
    GUARD(s2n_stuffer_skip_write(stuffer, length));
    uint8_t *data = stuffer->blob.data + stuffer->write_cursor - length;

    for (int i = 0; i < length; i++) {
        S2N_INVARIENT(i <= length);
        uint8_t shift = (length - i - 1) * CHAR_BIT;
        data[i] = (input >> (shift)) & UINT8_MAX;
    }
    POSTCONDITION_POSIX(s2n_stuffer_validate(stuffer));
    return S2N_SUCCESS;
}

int s2n_stuffer_reserve(struct s2n_stuffer *stuffer, struct s2n_stuffer_reservation *reservation, const uint8_t length)
{
    PRECONDITION_POSIX(s2n_stuffer_validate(stuffer));
    notnull_check(reservation);

    *reservation = (struct s2n_stuffer_reservation) {.stuffer = stuffer, .write_cursor = stuffer->write_cursor, .length = length};

    GUARD(s2n_stuffer_skip_write(stuffer, reservation->length));
    memset_check(stuffer->blob.data + reservation->write_cursor, S2N_WIPE_PATTERN, reservation->length);
    POSTCONDITION_POSIX(s2n_stuffer_reservation_validate(reservation));
    return S2N_SUCCESS;
}

int s2n_stuffer_read_uint8(struct s2n_stuffer *stuffer, uint8_t * u)
{
    GUARD(s2n_stuffer_read_bytes(stuffer, u, sizeof(uint8_t)));

    return S2N_SUCCESS;
}

int s2n_stuffer_write_uint8(struct s2n_stuffer *stuffer, const uint8_t u)
{
    GUARD(s2n_stuffer_write_bytes(stuffer, &u, sizeof(u)));

    return S2N_SUCCESS;
}

int s2n_stuffer_read_uint16(struct s2n_stuffer *stuffer, uint16_t * u)
{
    notnull_check(u);
    uint8_t data[sizeof(uint16_t)];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = data[0] << 8;
    *u |= data[1];

    return S2N_SUCCESS;
}

int s2n_stuffer_write_uint16(struct s2n_stuffer *stuffer, const uint16_t u)
{
    return s2n_stuffer_write_network_order(stuffer, u, sizeof(u));
}

int s2n_stuffer_reserve_uint16(struct s2n_stuffer *stuffer, struct s2n_stuffer_reservation *reservation)
{
    return s2n_stuffer_reserve(stuffer, reservation, sizeof(uint16_t));
}

int s2n_stuffer_read_uint24(struct s2n_stuffer *stuffer, uint32_t * u)
{
    notnull_check(u);
    uint8_t data[SIZEOF_UINT24];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = data[0] << 16;
    *u |= data[1] << 8;
    *u |= data[2];

    return S2N_SUCCESS;
}

int s2n_stuffer_write_uint24(struct s2n_stuffer *stuffer, const uint32_t u)
{
    return s2n_stuffer_write_network_order(stuffer, u, SIZEOF_UINT24);
}

int s2n_stuffer_reserve_uint24(struct s2n_stuffer *stuffer, struct s2n_stuffer_reservation *reservation)
{
    return s2n_stuffer_reserve(stuffer, reservation, SIZEOF_UINT24);
}

int s2n_stuffer_read_uint32(struct s2n_stuffer *stuffer, uint32_t * u)
{
    notnull_check(u);
    uint8_t data[sizeof(uint32_t)];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = ((uint32_t) data[0]) << 24;
    *u |= data[1] << 16;
    *u |= data[2] << 8;
    *u |= data[3];

    return S2N_SUCCESS;
}

int s2n_stuffer_write_uint32(struct s2n_stuffer *stuffer, const uint32_t u)
{
    return s2n_stuffer_write_network_order(stuffer, u, sizeof(u));
}

int s2n_stuffer_read_uint64(struct s2n_stuffer *stuffer, uint64_t * u)
{
    notnull_check(u);
    uint8_t data[sizeof(uint64_t)];

    GUARD(s2n_stuffer_read_bytes(stuffer, data, sizeof(data)));

    *u = ((uint64_t) data[0]) << 56;
    *u |= ((uint64_t) data[1]) << 48;
    *u |= ((uint64_t) data[2]) << 40;
    *u |= ((uint64_t) data[3]) << 32;
    *u |= ((uint64_t) data[4]) << 24;
    *u |= ((uint64_t) data[5]) << 16;
    *u |= ((uint64_t) data[6]) << 8;
    *u |= data[7];

    return S2N_SUCCESS;
}

int s2n_stuffer_write_uint64(struct s2n_stuffer *stuffer, const uint64_t u)
{
    return s2n_stuffer_write_network_order(stuffer, u, sizeof(u));
}

static int length_matches_value_check(uint32_t value, uint8_t length)
{
    /* Value is represented as a uint32_t, so shouldn't be assumed larger */
    S2N_ERROR_IF(length > sizeof(uint32_t), S2N_ERR_SIZE_MISMATCH);

    if (length < sizeof(uint32_t)) {
        /* Value should be less than the maximum for its length */
        S2N_ERROR_IF(value >= (0x01 << (length * 8)), S2N_ERR_SIZE_MISMATCH);
    }

    return S2N_SUCCESS;
}

static int s2n_stuffer_write_reservation_impl(struct s2n_stuffer_reservation* reservation, const uint32_t u)
{
    reservation->stuffer->write_cursor = reservation->write_cursor;
    PRECONDITION_POSIX(s2n_stuffer_validate(reservation->stuffer));

    GUARD(length_matches_value_check(u, reservation->length));
    GUARD(s2n_stuffer_write_network_order(reservation->stuffer, u, reservation->length));
    POSTCONDITION_POSIX(s2n_stuffer_validate(reservation->stuffer));
    return S2N_SUCCESS;
}

int s2n_stuffer_write_reservation(struct s2n_stuffer_reservation* reservation, const uint32_t u)
{
    PRECONDITION_POSIX(s2n_stuffer_reservation_validate(reservation));
    uint32_t old_write_cursor = reservation->stuffer->write_cursor;
    int result = s2n_stuffer_write_reservation_impl(reservation, u);
    reservation->stuffer->write_cursor = old_write_cursor;
    return result;
}

int s2n_stuffer_write_vector_size(struct s2n_stuffer_reservation* reservation)
{
    PRECONDITION_POSIX(s2n_stuffer_reservation_validate(reservation));
    uint32_t size = 0;
    GUARD(s2n_sub_overflow(reservation->stuffer->write_cursor, reservation->write_cursor, &size));
    GUARD(s2n_sub_overflow(size, reservation->length, &size));
    return s2n_stuffer_write_reservation(reservation, size);
}
