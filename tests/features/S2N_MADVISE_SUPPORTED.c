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

/* Keep in sync with utils/s2n_fork_detection.c */
#if defined(__FreeBSD__)
    /* FreeBSD requires POSIX compatibility off for its syscalls (enables __BSD_VISIBLE)
     * Without the below line, <sys/mman.h> cannot be imported (it requires __BSD_VISIBLE) */
    #undef _POSIX_C_SOURCE
#elif !defined(__APPLE__) && !defined(_GNU_SOURCE)
    #define _GNU_SOURCE
#endif

#include <stddef.h>
#include <sys/mman.h>

int main() {
    madvise(NULL, 0, 0);
    return 0;
}
