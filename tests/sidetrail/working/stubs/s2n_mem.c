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

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "error/s2n_errno.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

static long page_size = 4096;
static int use_mlock = 1;

int s2n_mem_init(void)
{
    GUARD(page_size = sysconf(_SC_PAGESIZE));
    if (getenv("S2N_DONT_MLOCK")) {
        use_mlock = 0;
    }

    return 0;
}

int s2n_mem_cleanup(void)
{
    page_size = 4096;
    use_mlock = 1;
    return 0;
}

int s2n_alloc(struct s2n_blob *b, uint32_t size)
{
    b->data = NULL;
    b->size = 0;
    b->allocated = 0;
    b->mlocked = 0;
    GUARD(s2n_realloc(b, size));
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
    /* if (size == 0) { */
    /*     return s2n_free(b); */
    /* } */

    /* blob already has space for the request */
    if (size < b->allocated) {
        b->size = size;
        return 0;
    }

    void *data;
    if (!use_mlock) {
        data = realloc(b->data, size);
        if (!data) {
            S2N_ERROR(S2N_ERR_ALLOC);
        }

        b->data = data;
        b->size = size;
        b->allocated = size;
        return 0;
    }

/*     /\* Page aligned allocation required for mlock *\/ */
/*     uint32_t allocate = page_size * (((size - 1) / page_size) + 1); */
/*     if (posix_memalign(&data, page_size, allocate)) { */
/*         S2N_ERROR(S2N_ERR_ALLOC); */
/*     } */

/*     if (b->size) { */
/*         memcpy_check(data, b->data, b->size); */
/*         GUARD(s2n_free(b)); */
/*     } */

/*     b->data = data; */
/*     b->size = size; */
/*     b->allocated = allocate; */

/* #ifdef MADV_DONTDUMP */
/*     if (madvise(b->data, size, MADV_DONTDUMP) < 0) { */
/*         GUARD(s2n_free(b)); */
/*         S2N_ERROR(S2N_ERR_MADVISE); */
/*     } */
/* #endif */

/*     if (mlock(b->data, size) < 0) { */
/*         GUARD(s2n_free(b)); */
/*         S2N_ERROR(S2N_ERR_MLOCK); */
/*     } */
/*     b->mlocked = 1; */

    return 0;
}

int s2n_free(struct s2n_blob *b)
{
    int munlock_rc = 0;
    if (b->mlocked) {
        munlock_rc = munlock(b->data, b->size);
    }

    free(b->data);
    b->data = NULL;
    b->size = 0;
    b->allocated = 0;

    if (munlock_rc < 0) {
        S2N_ERROR(S2N_ERR_MUNLOCK);
    }
    b->mlocked = 0;

    return 0;
}

int s2n_dup(struct s2n_blob *from, struct s2n_blob *to)
{
    eq_check(to->size, 0);
    eq_check(to->data, NULL);

    GUARD(s2n_alloc(to, from->size));
    
    memcpy_check(to->data, from->data, to->size);

    return 0;
}
