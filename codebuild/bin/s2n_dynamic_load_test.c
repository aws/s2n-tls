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

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

static void *s2n_load_dynamic_lib(void *ctx)
{
    const char *s2n_so_path = ctx;

    void *s2n_so = dlopen(s2n_so_path, RTLD_NOW);
    if (!s2n_so) {
        printf("Error dynamically loading libs2n\n");
        printf("%s\n", dlerror());
        exit(1);
    }

    int (*s2n_init_dl)(void) = NULL;
    *(void **) (&s2n_init_dl) = dlsym(s2n_so, "s2n_init");
    if (dlerror()) {
        printf("Error dynamically loading s2n_init\n");
        exit(1);
    }

    int (*s2n_cleanup_final_dl)(void) = NULL;
    *(void **) (&s2n_cleanup_final_dl) = dlsym(s2n_so, "s2n_cleanup_final");
    if (dlerror()) {
        printf("Error dynamically loading s2n_cleanup_final\n");
        exit(1);
    }

    int (*s2n_errno_location_dl)(void) = NULL;
    *(void **) (&s2n_errno_location_dl) = dlsym(s2n_so, "s2n_errno_location");
    if (dlerror()) {
        printf("Error dynamically loading s2n_errno_location\n");
        exit(1);
    }

    const char *(*s2n_strerror_debug_dl)(int error, const char *lang) = NULL;
    *(void **) (&s2n_strerror_debug_dl) = dlsym(s2n_so, "s2n_strerror_debug");
    if (dlerror()) {
        printf("Error dynamically loading s2n_strerror_debug\n");
        exit(1);
    }

    if ((*s2n_init_dl)()) {
        int s2n_errno = (*s2n_errno_location_dl)();
        fprintf(stderr, "Error calling s2n_init: '%s'\n", (*s2n_strerror_debug_dl)(s2n_errno, "EN"));
        exit(1);
    }
    if ((*s2n_cleanup_final_dl)()) {
        int s2n_errno = (*s2n_errno_location_dl)();
        fprintf(stderr, "Error calling s2n_cleanup_final: '%s'\n", (*s2n_strerror_debug_dl)(s2n_errno, "EN"));
        exit(1);
    }

    /* TODO: https://github.com/aws/s2n-tls/issues/4827
     * This is a bug. We can get this test to
     * pass by commenting out dlclose, however this issue eventually
     * needs to be fixed.
    if (dlclose(s2n_so)) {
        printf("Error closing libs2n\n");
        printf("%s\n", dlerror());
        exit(1);
    }
    */

    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: s2n_dynamic_load_test <path to s2n shared object>\n");
        exit(1);
    }

    /* s2n-tls library can be dynamically loaded and cleaned up safely 
     *
     * We can't use any s2n test macros because this test doesn't get linked to 
     * s2n during compile-time. This test is in a loop to make sure that we are
     * cleaning up pthread keys properly.
     */
    for (size_t i = 0; i <= PTHREAD_KEYS_MAX + 1; i++) {
        pthread_t thread_id = { 0 };
        if (pthread_create(&thread_id, NULL, &s2n_load_dynamic_lib, argv[1])) {
            printf("Error creating thread at loop index: %li\n", i);
            exit(1);
        }
        if (pthread_join(thread_id, NULL)) {
            printf("Error joining thread at loop index: %li\n", i);
            exit(1);
        }
    }

    return 0;
}
