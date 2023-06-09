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

#include "s2n.h"

int s2n_example_recv(struct s2n_connection *conn, uint8_t *buffer, size_t buffer_size)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    int bytes_read = 0;
    while (bytes_read < buffer_size) {
        int r = s2n_recv(conn, buffer + bytes_read, buffer_size - bytes_read, &blocked);
        if (r == 0) {
            break;
        } else if (r > 0) {
            bytes_read += r;
        } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return -1;
        }
    }
    fprintf(stdout, "Received: %.*s\n", bytes_read, buffer);
    return 0;
}

int s2n_example_recv_echo(struct s2n_connection *conn, uint8_t *buffer, size_t buffer_size)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    while (true) {
        int r = s2n_recv(conn, buffer, buffer_size, &blocked);
        if (r == 0) {
            fprintf(stdout, "End of data.\n");
            return 0;
        } else if (r > 0) {
            fprintf(stdout, "Received: %.*s\n", r, buffer);
        } else if (r < 0 && s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return -1;
        }
    }
}
