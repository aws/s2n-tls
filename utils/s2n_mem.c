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
    notnull_check(b);
    const struct s2n_blob temp = {0};
    *b = temp;
    GUARD(s2n_realloc(b, size));
    return 0;
}

/* A blob is growable if it is either explicitly marked as such, or if it contains no data */
bool s2n_blob_is_growable(const struct s2n_blob* b)
{
  return b && (b->growable || (b->data == NULL && b->size == 0 && b->allocated == 0));
}

static int s2n_get_memory(struct s2n_blob *b, uint32_t size)
{
    if(use_mlock) {
        /* Page aligned allocation required for mlock */
        uint32_t allocate = page_size * (((size - 1) / page_size) + 1);
	*b = (struct s2n_blob) {.data = NULL, .size = size, .allocated = allocate, .mlocked = 1, .growable = 1};
	S2N_ERROR_IF(posix_memalign((void**) &b->data, page_size, allocate), S2N_ERR_ALLOC);
#ifdef MADV_DONTDUMP
	S2N_ERROR_IF(madvise(b->data, b->size, MADV_DONTDUMP) < 0, S2N_ERR_MADVISE);
#endif
	S2N_ERROR_IF(mlock(b->data, b->size) < 0, S2N_ERR_MLOCK);
    } else {
        *b = (struct s2n_blob) {.data = calloc(size, 1), .size = size, .allocated = size, .mlocked = 0, .growable = 1};
    }
    S2N_ERROR_IF(b->data == NULL, S2N_ERR_ALLOC);
    return S2N_SUCCESS;
}

/* Tries to realloc the requested bytes.
 * If successful, updates *b.
 * If failed, *b remains unchanged
 */
int s2n_realloc(struct s2n_blob *b, uint32_t size)
{
    notnull_check(b);
    S2N_ERROR_IF(!s2n_blob_is_growable(b), S2N_ERR_RESIZE_STATIC_BLOB);
    if (size == 0) {
        return s2n_free(b);
    }

    /* blob already has space for the request */
    if (size < b->allocated) {
        b->size = size;
        return S2N_SUCCESS;
    }

    struct s2n_blob new_memory = {0};
    if (s2n_get_memory(&new_memory, size) < 0) {
        GUARD(s2n_free(&new_memory));
        S2N_ERROR_PRESERVE_ERRNO();
    }

    if (b->size) {
        memcpy_check(new_memory.data, b->data, b->size);
        GUARD(s2n_free(b));
    }

    *b = new_memory;
    return S2N_SUCCESS;
}

int s2n_free(struct s2n_blob *b)
{
    S2N_ERROR_IF(!s2n_blob_is_growable(b), S2N_ERR_FREE_STATIC_BLOB);
    /* To avoid memory leaks, still free the data even if we can't unlock / wipe it */
    int zero_rc = s2n_blob_zero(b);
    int munlock_rc = b->mlocked ? munlock(b->data, b->size) : 0;
    free(b->data);
    *b = (struct s2n_blob) {0};
    S2N_ERROR_IF(munlock_rc < 0, S2N_ERR_MUNLOCK);
    GUARD(zero_rc);
    return S2N_SUCCESS;
}

int s2n_free_object(uint8_t **p_data, uint32_t size)
{
    notnull_check(p_data);

    if (*p_data == NULL) {
        return 0;
    }
    struct s2n_blob b = {.data = *p_data, .size = size, .mlocked = use_mlock, .growable = 1};

    /* s2n_free() will call free() even if it returns error (for a growable blob).
    ** This makes sure *p_data is not used after free() */
    *p_data = NULL;

    return s2n_free(&b);
}

int s2n_dup(struct s2n_blob *from, struct s2n_blob *to)
{
    eq_check(to->size, 0);
    eq_check(to->data, NULL);
    ne_check(from->size, 0);
    ne_check(from->data, NULL);

    GUARD(s2n_alloc(to, from->size));
    
    memcpy_check(to->data, from->data, to->size);

    return 0;
}
