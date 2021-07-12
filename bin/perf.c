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

#include <s2n.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_endian.h"
#include "utils/s2n_safety.h"
#include "common.h"

uint64_t read_uint64(uint8_t *data)
{
    uint64_t u = 0;
    u |= ((uint64_t) data[0]);
    u |= ((uint64_t) data[1]) << (1 * 8);
    u |= ((uint64_t) data[2]) << (2 * 8);
    u |= ((uint64_t) data[3]) << (3 * 8);
    u |= ((uint64_t) data[4]) << (4 * 8);
    u |= ((uint64_t) data[5]) << (5 * 8);
    u |= ((uint64_t) data[6]) << (6 * 8);
    u |= ((uint64_t) data[7]) << (7 * 8);
    u = be64toh(u);
    return u;
}

void write_uint64(uint8_t *data, uint64_t u)
{
    u = htobe64(u);
    data[0] = (u) & UINT8_MAX;
    data[1] = (u >> (1 * 8)) & UINT8_MAX;
    data[2] = (u >> (2 * 8)) & UINT8_MAX;
    data[3] = (u >> (3 * 8)) & UINT8_MAX;
    data[4] = (u >> (4 * 8)) & UINT8_MAX;
    data[5] = (u >> (5 * 8)) & UINT8_MAX;
    data[6] = (u >> (6 * 8)) & UINT8_MAX;
    data[7] = (u >> (7 * 8)) & UINT8_MAX;
}

static int send(struct s2n_connection *conn, uint8_t *buffer,  uint32_t left, s2n_blocked_status *blocked_status)
{
    uint32_t i = 0;
    while (i < left) {
        int out = s2n_send(conn, &buffer[i], left - i, blocked_status);
        if (out < 0) {
            fprintf(stderr, "Error writing to connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            s2n_print_stacktrace(stdout);
            return S2N_FAILURE;
        }
        i += out;
    }

    return S2N_SUCCESS;
}

static int recv(struct s2n_connection *conn, uint8_t *buffer, uint32_t left, s2n_blocked_status *blocked_status)
{
    uint32_t i = 0;
    while (i < left) {
        int out = s2n_recv(conn, &buffer[i], left - i, blocked_status);
        if (out < 0) {
            fprintf(stderr, "Error writing to connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            s2n_print_stacktrace(stdout);
            return S2N_FAILURE;
        }
        i += out;
    }

    return S2N_SUCCESS;
}

int perf_server_handler(struct s2n_connection *conn)
{
    printf("handling perf connection\n");
    uint8_t buffer[UINT16_MAX] = { 0 };
    uint32_t buffer_len = sizeof(buffer);
    uint64_t send_len = 0;

    s2n_blocked_status blocked = 0;

    /* read the amount the client wants back */
    POSIX_GUARD(s2n_recv(conn, &buffer, sizeof(uint64_t), &blocked));
    send_len = read_uint64(buffer);

    while (send_len) {
        uint32_t buffer_remaining = send_len < buffer_len ? send_len : buffer_len;
        POSIX_GUARD(send(conn, buffer, buffer_remaining, &blocked));
        send_len -= buffer_remaining;
    }

    /* TODO implement recv */

    fprintf(stdout, "Done. Closing connection.\n\n");

    return S2N_SUCCESS;
}

int perf_client_handler(struct s2n_connection *conn, uint64_t send_len, uint64_t recv_len)
{
    uint8_t buffer[UINT16_MAX] = { 0 };
    uint32_t buffer_len = sizeof(buffer);
    uint64_t total_send_len = send_len;
    uint64_t total_recv_len = recv_len;

    s2n_blocked_status blocked = 0;

    /* write the amount the client wants back */
    write_uint64(buffer, recv_len);

    /* account for the length prefix */
    POSIX_GUARD(send(conn, buffer, 8, &blocked));

    while (recv_len) {
        uint32_t buffer_remaining = recv_len < buffer_len ? recv_len : buffer_len;
        POSIX_GUARD(recv(conn, buffer, buffer_remaining, &blocked));
        recv_len -= buffer_remaining;
    }

    /* TODO implement send */

    fprintf(stdout, "Received %luB.\n", total_recv_len);
    fprintf(stdout, "    Sent %luB.\n\n", total_send_len);

    return S2N_SUCCESS;
}
