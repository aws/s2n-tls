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

static void * s2n_load_dynamic_lib(void *ctx)
{
    const char *s2n_so_path = ctx;

    void *s2n_so = dlopen(s2n_so_path, RTLD_NOW);
    if (!s2n_so) {
        exit(1);
    }

    int (*s2n_init_dl)(void) = NULL;
    *(void **)(&s2n_init_dl) = dlsym(s2n_so, "s2n_init");
    if(dlerror()) {
        exit(1);
    }

    int (*s2n_cleanup_dl)(void) = NULL;
    *(void **)(&s2n_cleanup_dl) = dlsym(s2n_so, "s2n_cleanup");
    if(dlerror()) {
        exit(1);
    }

    if ((*s2n_init_dl)()) {
        exit(1);
    }
    if((*s2n_cleanup_dl)()) {
        exit(1);
    }
    
    if(dlclose(s2n_so)) {
        exit(1);
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: s2n_dynamic_load_test <path to s2n shared object>\n");
        exit(1);
    }

    /** s2n-tls shared object can be dynamically loaded and cleaned up safely **/
    {
        pthread_t thread_id = { 0 };
        if(pthread_create(&thread_id, NULL, &s2n_load_dynamic_lib, argv[1])) {
            exit(1);
        }
        if(pthread_join(thread_id, NULL)) {
            exit(1);
        }
    }

    return 0;
}