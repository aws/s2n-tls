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

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "error/s2n_errno.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

static long page_size = 4096;

int s2n_mem_init(void)
{
    POSIX_GUARD(page_size = sysconf(_SC_PAGESIZE));

    return 0;
}

int s2n_mem_cleanup(void)
{
    page_size = 4096;
    return 0;
}

int s2n_alloc(struct s2n_blob *b, uint32_t size)
{
    b->data = NULL;
    b->size = 0;
    b->allocated = 0;
    POSIX_GUARD(s2n_realloc(b, size));
    return 0;
}

void *realloc( void *ptr, size_t new_size )
{
  /* just leave it undet for now */
  void* ret = malloc(new_size);
  return ret;
}

int s2n_realloc(struct s2n_blob *b, uint32_t size)
{
    /* blob already has space for the request */
    if (size < b->allocated) {
        b->size = size;
        return 0;
    }

    void *data = realloc(b->data, size);
    if (!data) {
        POSIX_BAIL(S2N_ERR_ALLOC);
    }

    b->data = data;
    b->size = size;
    b->allocated = size;
    return 0;
}

int s2n_free(struct s2n_blob *b)
{
    free(b->data);
    b->data = NULL;
    b->size = 0;
    b->allocated = 0;

    return 0;
}

int s2n_dup(struct s2n_blob *from, struct s2n_blob *to)
{
    POSIX_ENSURE_EQ(to->size, 0);
    POSIX_ENSURE_EQ(to->data, NULL);

    POSIX_GUARD(s2n_alloc(to, from->size));
    
    POSIX_CHECKED_MEMCPY(to->data, from->data, to->size);

    return 0;
}
