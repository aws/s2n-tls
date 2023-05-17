/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0.
*/


#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* load_unload(void *ctx)
{
    const char *s2n_so_path = ctx;

    void *s2n_so = dlopen(s2n_so_path, RTLD_NOW);

    int (*s2n_init)(void) = NULL;
    *(void **)(&s2n_init) = dlsym(s2n_so, "s2n_init");

    int (*s2n_cleanup)(void) = NULL;
    *(void **)(&s2n_cleanup) = dlsym(s2n_so, "s2n_cleanup");

    if ((*s2n_init)() != 0) {
       exit(1);
    }

    (*s2n_cleanup)();

    dlclose(s2n_so);

    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: s2n_unload_single <path to s2n shared object>\n");
        exit(1);
    }

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, load_unload, argv[1])) {
        exit(1);
    }

    pthread_join(thread_id, NULL);

    return 0;
}
