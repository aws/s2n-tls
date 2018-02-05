/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_suites.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

static void s2n_cleanup_atexit(void);

int s2n_init(void)
{
    GUARD(s2n_fips_init());
    GUARD(s2n_mem_init());
    GUARD(s2n_rand_init());
    GUARD(s2n_cipher_suites_init());

    S2N_ERROR_IF(atexit(s2n_cleanup_atexit) != 0, S2N_ERR_ATEXIT);

    return 0;
}

int s2n_cleanup(void)
{
    GUARD(s2n_rand_cleanup_thread());

    return 0;
}

static void s2n_cleanup_atexit(void)
{
    s2n_rand_cleanup_thread();
    s2n_cipher_suites_cleanup();
    s2n_rand_cleanup();
    s2n_mem_cleanup();
    s2n_wipe_static_configs();
}

