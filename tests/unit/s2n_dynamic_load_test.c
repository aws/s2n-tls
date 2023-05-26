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

static void *s2n_load_dynamic_lib(void *ctx)
{
    const char *s2n_so_path = ctx;

    void *s2n_so = dlopen(s2n_so_path, RTLD_NOW);
    if (!s2n_so) {
        exit(1);
    }

    int (*s2n_init_dl)(void) = NULL;
    *(void **) (&s2n_init_dl) = dlsym(s2n_so, "s2n_init");
    if (dlerror()) {
        exit(1);
    }

    int (*s2n_cleanup_dl)(void) = NULL;
    *(void **) (&s2n_cleanup_dl) = dlsym(s2n_so, "s2n_cleanup");
    if (dlerror()) {
        exit(1);
    }

    if ((*s2n_init_dl)()) {
        exit(1);
    }
    if ((*s2n_cleanup_dl)()) {
        exit(1);
    }

    if (dlclose(s2n_so)) {
        exit(1);
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    /* We don't want this test to run with all the other unit tests, so we fail quietly
     * if the shared library wasn't specified. */
    if (argc != 2) {
        return 0;
    }

    /* s2n-tls library can be dynamically loaded and cleaned up safely 
     *
     * We can't use any s2n test macros because then the compiler gets
     * confused about whether or not to link the s2n functions.
     */
    {
        pthread_t thread_id = { 0 };
        if (pthread_create(&thread_id, NULL, &s2n_load_dynamic_lib, argv[1])) {
            exit(1);
        }
        if (pthread_join(thread_id, NULL)) {
            exit(1);
        }
    }

    return 0;
}
