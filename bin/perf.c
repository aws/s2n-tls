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
#include <time.h>

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_endian.h"
#include "utils/s2n_safety.h"
#include "common.h"

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
    bool recv_remaining = true;

    s2n_blocked_status blocked = 0;

    /* read the amount the client wants back */
    POSIX_GUARD(s2n_recv(conn, &buffer, 8, &blocked));
    send_len = *(uint64_t *) &buffer;
    send_len = be64toh(send_len);

    while (send_len) {
        uint32_t buffer_remaining = send_len < buffer_len ? send_len : buffer_len;
        POSIX_GUARD(send(conn, buffer, buffer_remaining, &blocked));
        send_len -= buffer_remaining;
    }

    /* TODO implement recv */

    fprintf(stdout, "Done. Closing connection.\n\n");

    return 0;
}

int perf_client_handler(struct s2n_connection *conn, uint64_t send_len, uint64_t recv_len)
{
    uint8_t buffer[UINT16_MAX] = { 0 };
    uint32_t buffer_len = sizeof(buffer);
    uint64_t total_send_len = send_len;
    uint64_t total_recv_len = recv_len;

    s2n_blocked_status blocked = 0;

    /* write the amount the client wants back */
    *((uint64_t *) buffer) = htobe64(recv_len);

    /* account for the length prefix */
    send_len += 8;
    POSIX_GUARD(send(conn, buffer, 8, &blocked));

    clock_t begin = clock();

    while (recv_len) {
        uint32_t buffer_remaining = recv_len < buffer_len ? recv_len : buffer_len;
        POSIX_GUARD(recv(conn, buffer, buffer_remaining, &blocked));
        recv_len -= buffer_remaining;
    }

    /* TODO implement send */

    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    double recv_mbps = (double)total_recv_len / time_spent / 1000000.0;
    double send_mbps = (double)total_send_len / time_spent / 1000000.0;

    fprintf(stdout, "Received %dMiB/s.\n", (uint32_t)recv_mbps);
    fprintf(stdout, "    Sent %dMiB/s.\n\n", (uint32_t)send_mbps);

    return 0;
}
