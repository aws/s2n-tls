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

#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

#include "api/s2n.h"
#include "crypto/s2n_drbg.h"
#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *blob) {

    /* If fuzzing, only generate "fake" random numbers in order to ensure that fuzz tests are deterministic and repeatable.
     * This function should generate non-zero values since this function may be called repeatedly at startup until a
     * non-zero value is generated.
     */
    GUARD_AS_POSIX(s2n_get_urandom_data(blob));
    drbg->bytes_used += blob->size;
    return S2N_SUCCESS;
}

int s2n_stuffer_send_to_fd(struct s2n_stuffer *stuffer, const int wfd, const uint32_t len, uint32_t *bytes_sent)
{
    /* Override the original s2n_stuffer_send_to_fd to check if the write file descriptor is -1, and if so, skip
     * writing anything. This is to speed up fuzz tests that write unnecessary data that is never actually read.
     */
    if(wfd == -1){
       stuffer->read_cursor += len;
       return len;
    }

    /* Otherwise, call the original s2n_stuffer_send_to_fd() */
    typedef int (*orig_s2n_stuffer_send_to_fd_func_type)(struct s2n_stuffer *stuffer, const int wfd, const uint32_t len, uint32_t *bytes_sent);
    orig_s2n_stuffer_send_to_fd_func_type orig_s2n_stuffer_send_to_fd;
    orig_s2n_stuffer_send_to_fd = (orig_s2n_stuffer_send_to_fd_func_type) dlsym(RTLD_NEXT, "s2n_stuffer_send_to_fd");
    GUARD_NONNULL(orig_s2n_stuffer_send_to_fd);
    GUARD(orig_s2n_stuffer_send_to_fd(stuffer, wfd, len, bytes_sent));
    return S2N_SUCCESS;
}

S2N_RESULT s2n_get_urandom_data(struct s2n_blob *blob){

    /* If fuzzing, only generate "fake" random numbers in order to ensure that fuzz tests are deterministic and repeatable.
     * This function should generate non-zero values since this function may be called repeatedly at startup until a
     * non-zero value is generated.
     */
    for(int i=0; i < blob->size; i++){
       blob->data[i] = 4; /* Fake RNG. Chosen by fair dice roll. https://xkcd.com/221/ */
    }
    return S2N_RESULT_OK;
}
