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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils/s2n_blob.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#include "testlib/s2n_testlib.h"

static int buffer_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *in_buf;
    int n_read, n_avail;


    if (buf == NULL) {
        return 0;
    }

    in_buf = (struct s2n_stuffer *) io_context;
    if (in_buf == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* read the number of bytes requested or less if it isn't available */
    n_avail = s2n_stuffer_data_available(in_buf);
    n_read = (len < n_avail) ? len : n_avail;

    if (n_read == 0) {
        errno = EAGAIN;
        return -1;
    }

    s2n_stuffer_read_bytes(in_buf, buf, n_read);
    return n_read;
}

static int buffer_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *out;

    if (buf == NULL) {
        return 0;
    }

    out = (struct s2n_stuffer *) io_context;
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (s2n_stuffer_write_bytes(out, buf, len) < 0) {
        errno = EAGAIN;
        return -1;
    }

    return len;
}

/* The connection will read/write to/from a stuffer, instead of sockets */
int s2n_connection_set_io_stuffers(struct s2n_stuffer *input, struct s2n_stuffer *output, struct s2n_connection *conn)
{
    /* Set Up Callbacks*/
    GUARD(s2n_connection_set_recv_cb(conn, &buffer_read));
    GUARD(s2n_connection_set_send_cb(conn, &buffer_write));

    /* Set up Callback Contexts to use stuffers */
    GUARD(s2n_connection_set_recv_ctx(conn, input));
    GUARD(s2n_connection_set_send_ctx(conn, output));

    return 0;
}

void s2n_print_bytearray(uint8_t *buf, uint32_t len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 8 == 0) {
            printf(" ");
        }
        if ((i + 1) % 40 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void s2n_print_blob(struct s2n_blob *blob, const char *name)
{
    printf("%s Blob (size: %d)\n", name, blob->size);
    s2n_print_bytearray(blob->data, blob->size);
}

void s2n_print_stuffer(struct s2n_stuffer *stuffer, const char *name)
{
    printf("%s Stuffer (write: %d, read: %d, size: %d)\n", name, stuffer->write_cursor, stuffer->read_cursor, stuffer->blob.size);
    s2n_print_bytearray(stuffer->blob.data, stuffer->write_cursor);
}

void s2n_print_connection(struct s2n_connection *conn, const char *marker)
{
    printf("marker: %s\n", marker);

    s2n_print_blob(&conn->header_in.blob, "HEADER IN");
    s2n_print_stuffer(&conn->in, "IN");
    s2n_print_stuffer(&conn->out, "OUT");
}
