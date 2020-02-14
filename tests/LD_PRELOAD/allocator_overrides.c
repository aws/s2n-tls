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

#include <string.h>

/* Define _GNU_SOURCE to get RTLD_NEXT definition from dlfcn.h */
#define _GNU_SOURCE
#include <dlfcn.h>

/* Overrides will work only if RTLD_NEXT is defined */
#ifdef RTLD_NEXT

/* if we use glibc, include malloc.h for malloc_usable_size */
#ifdef __GLIBC__
#include <malloc.h>
#define HAVE_MALLOC_USABLE_SIZE
#endif

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

    if (orig_realloc == NULL) {
        /* C99 forbids converting void * to function pointers, so direct
         * assignemnt fails with -pedantic. Yet dlsym is still used to return
         * function pointers in standard library, despite that it returns
         * void *. Casting function pointer to void ** and dereferencing it
         * allows to bypass compiler warnings. */
        *(void **) &orig_realloc = dlsym(RTLD_NEXT, "realloc");
    }


#ifdef HAVE_MALLOC_USABLE_SIZE
    /* If malloc_usable_size is available, we can get the size of previously
     * allocated buffer, to find out how many new bytes we've allocated.
     * Get the usable size for ptr before we call realloc, because realloc may call
     * free() on the original pointer. */
    size_t ptr_alloc_size = malloc_usable_size(ptr);
#endif

    p = orig_realloc(ptr, size);

#ifdef HAVE_MALLOC_USABLE_SIZE
    size_t p_alloc_size = malloc_usable_size(p);

    /* If call succeeded and we're enlarging memory, fill the extension with
     * non-zero data */
    if (p && p_alloc_size > ptr_alloc_size) {
        memset((char *) p + ptr_alloc_size, 0xff, p_alloc_size - ptr_alloc_size);
    }
#else
    /* If we're allocating new buffer and the call succeeded, fill the buffer
     * with non-zero data*/
    if (p && !ptr) {
        memset(p, 0xff, size);
    }
#endif

    return p;
}

#endif
