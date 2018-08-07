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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_stuffer_recv_from_fd(struct s2n_stuffer *stuffer, int rfd, uint32_t len)
{

    /* Make sure we have enough space to write */
    GUARD(s2n_stuffer_skip_write(stuffer, len));

    /* "undo" the skip write */
    stuffer->write_cursor -= len;

  READ:
    errno = 0;
    int r = read(rfd, stuffer->blob.data + stuffer->write_cursor, len);
    if (r < 0) {
        if (errno == EINTR) {
            goto READ;
        }
        return -1;
    }

    /* Record just how many bytes we have written */
    stuffer->write_cursor += r;
    stuffer->wiped = 0;

    return r;
}

int s2n_stuffer_send_to_fd(struct s2n_stuffer *stuffer, int wfd, uint32_t len)
{
    /* Make sure we even have the data */
    GUARD(s2n_stuffer_skip_read(stuffer, len));

    /* "undo" the skip read */
    stuffer->read_cursor -= len;

  WRITE:
    errno = 0;
    int w = write(wfd, stuffer->blob.data + stuffer->read_cursor, len);
    if (w < 0) {
        if (errno == EINTR) {
            goto WRITE;
        }
        return -1;
    }

    stuffer->read_cursor += w;

    return w;
}

int s2n_stuffer_alloc_ro_from_fd(struct s2n_stuffer *stuffer, int rfd)
{
    struct stat st = {0};

    S2N_ERROR_IF(fstat(rfd, &st) < 0, S2N_ERR_FSTAT);

    stuffer->blob.data = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, rfd, 0);
    S2N_ERROR_IF(stuffer->blob.data == MAP_FAILED, S2N_ERR_MMAP);

    stuffer->blob.size = st.st_size;

    return s2n_stuffer_init(stuffer, &stuffer->blob);
}

int s2n_stuffer_alloc_ro_from_file(struct s2n_stuffer *stuffer, const char *file)
{
    int fd;

  OPEN:
    fd = open(file, O_RDONLY);
    if (fd < 0) {
        if (errno == EINTR) {
            goto OPEN;
        }
        S2N_ERROR(S2N_ERR_OPEN);
    }

    int r = s2n_stuffer_alloc_ro_from_fd(stuffer, fd);

    GUARD(close(fd));

    return r;
}
