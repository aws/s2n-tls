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
#include "crypto/s2n_fips.h"

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_security_policies.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/s2n_tls13_secrets.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety_macros.h"

#include "openssl/opensslv.h"

#include "pq-crypto/s2n_pq.h"

#include <pthread.h>

static void s2n_cleanup_atexit(void);

unsigned long s2n_get_openssl_version(void)
{
    return OPENSSL_VERSION_NUMBER;
}

static pthread_t main_thread = 0;
static bool initialized = false;
static bool atexit_cleanup = true;
int s2n_disable_atexit(void) {
    POSIX_ENSURE(!initialized, S2N_ERR_INITIALIZED);
    atexit_cleanup = false;
    return S2N_SUCCESS;
}

int s2n_init(void)
{
    main_thread = pthread_self();
    POSIX_GUARD(s2n_fips_init());
    POSIX_GUARD(s2n_mem_init());
    POSIX_GUARD_RESULT(s2n_rand_init());
    POSIX_GUARD(s2n_cipher_suites_init());
    POSIX_GUARD(s2n_security_policies_init());
    POSIX_GUARD(s2n_config_defaults_init());
    POSIX_GUARD(s2n_extension_type_init());
    POSIX_GUARD_RESULT(s2n_pq_init());
    POSIX_GUARD_RESULT(s2n_tls13_empty_transcripts_init());

    if (atexit_cleanup) {
        POSIX_ENSURE_OK(atexit(s2n_cleanup_atexit), S2N_ERR_ATEXIT);
    }

    if (getenv("S2N_PRINT_STACKTRACE")) {
        s2n_stack_traces_enabled_set(true);
    }

    initialized = true;

    return S2N_SUCCESS;
}

static bool s2n_cleanup_atexit_impl(void)
{
    /* all of these should run, regardless of result, but the
     * values to need to be consumed to prevent warnings */

    /* the configs need to be wiped before resetting the memory callbacks */
    s2n_wipe_static_configs();

    bool a = s2n_result_is_ok(s2n_rand_cleanup_thread());
    bool b = s2n_result_is_ok(s2n_rand_cleanup());
    bool c = s2n_mem_cleanup() == 0;

    return a && b && c;
}

int s2n_cleanup(void)
{
    /* s2n_cleanup is supposed to be called from each thread before exiting,
     * so ensure that whatever clean ups we have here are thread safe */
    POSIX_GUARD_RESULT(s2n_rand_cleanup_thread());

    /* If this is the main thread and atexit cleanup is disabled,
     * perform final cleanup now */
    if (pthread_equal(pthread_self(), main_thread) && !atexit_cleanup) {
        POSIX_ENSURE(s2n_cleanup_atexit_impl(), S2N_ERR_ATEXIT);
    }
    return 0;
}

static void s2n_cleanup_atexit(void)
{
    s2n_cleanup_atexit_impl();
}
