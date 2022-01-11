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

/* Target Functions: s2n_stuffer_pem_read_encapsulation_line s2n_stuffer_pem_read_contents */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tests/s2n_test.h"
#include "utils/s2n_safety.h"

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    struct s2n_stuffer in = {0};
    struct s2n_stuffer out = {0};

    POSIX_GUARD(s2n_stuffer_alloc(&in, len + 1));
    POSIX_GUARD(s2n_stuffer_alloc(&out, len));
    POSIX_GUARD(s2n_stuffer_write_bytes(&in, buf, len));

    s2n_stuffer_certificate_from_pem(&in, &out);

    /* Reset in and out buffers */
    POSIX_GUARD(s2n_stuffer_reread(&in));
    POSIX_GUARD(s2n_stuffer_wipe(&out));

    s2n_stuffer_dhparams_from_pem(&in, &out);

    POSIX_GUARD(s2n_stuffer_free(&in));
    POSIX_GUARD(s2n_stuffer_free(&out));

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
