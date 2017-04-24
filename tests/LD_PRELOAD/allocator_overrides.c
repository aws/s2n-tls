/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#define _GNU_SOURCE

#include <dlfcn.h>
#include <string.h>
#include <malloc.h>

typedef int (*posix_memalign_fn)(void **memptr, size_t alignment, size_t size);
typedef void *(*realloc_fn)(void *ptr, size_t size);

posix_memalign_fn orig_posix_memalign = NULL;
realloc_fn orig_realloc = NULL;

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    /* Override original posix_memalign to fill allocated memory with some data
     * to catch errors due to missing initialization */
    int rc;

    if (orig_posix_memalign == NULL) {
        /* C99 forbids converting void * to function pointers, so direct
         * assignemnt fails with -pedantic. Yet dlsym is still used to return
         * function pointers in standard library, despite that it returns
         * void *. Casting function pointer to void ** and dereferencing it
         * allows to bypass compiler warnings. */
        *(void **) &orig_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    }

    rc = orig_posix_memalign(memptr, alignment, size);

    memset(*memptr, 0xff, size);

    return rc;
}

void *realloc(void *ptr, size_t size)
{
    /* Override original realloc to fill allocated memory with some data to
     * catch errors due to missing initialization */
    void *p;
    size_t ptr_alloc_size;

    if (orig_realloc == NULL) {
        /* C99 forbids converting void * to function pointers, so direct
         * assignemnt fails with -pedantic. Yet dlsym is still used to return
         * function pointers in standard library, despite that it returns
         * void *. Casting function pointer to void ** and dereferencing it
         * allows to bypass compiler warnings. */
        *(void **) &orig_realloc = dlsym(RTLD_NEXT, "realloc");
    }

    ptr_alloc_size = malloc_usable_size(ptr);
    p = orig_realloc(ptr, size);

    /* If call succeeded and we're enlarging memory, fill the extension with
     * some random data */
    if (p && size > ptr_alloc_size) {
        memset((char *) p + ptr_alloc_size, 0xff, size - ptr_alloc_size);
    }

    return p;
}
