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

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

int s2n_stuffer_alloc_ro_from_hex_string(struct s2n_stuffer *stuffer, const char *str)
{
    DEFER_CLEANUP(struct s2n_blob hex = { 0 }, s2n_free);
    /* Copying the hex into heap memory to handle the 'const' isn't exactly efficient,
     * but for a testlib method it is sufficient.
     */
    POSIX_GUARD(s2n_alloc(&hex, strlen(str)));
    POSIX_CHECKED_MEMCPY(hex.data, str, hex.size);

    POSIX_GUARD(s2n_stuffer_alloc(stuffer, strlen(str) / 2));
    POSIX_GUARD_RESULT(s2n_stuffer_read_hex(stuffer, &hex));
    return S2N_SUCCESS;
}
