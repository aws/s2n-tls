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

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_client_extensions.h"
#include "tls/extensions/s2n_client_key_share.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#include "openssl/opensslv.h"

static void s2n_cleanup_atexit(void);

unsigned long s2n_get_openssl_version(void)
{
    return OPENSSL_VERSION_NUMBER;
}

int s2n_init(void)
{
    GUARD(s2n_fips_init());
    GUARD(s2n_mem_init());
    GUARD(s2n_rand_init());
    GUARD(s2n_cipher_suites_init());
    GUARD(s2n_cipher_preferences_init());
    GUARD(s2n_config_defaults_init());

    S2N_ERROR_IF(atexit(s2n_cleanup_atexit) != 0, S2N_ERR_ATEXIT);

    /* Set the supported extension mask bits for each of the recognized
     * extensions */
    static const uint16_t extensions[] = {
        TLS_EXTENSION_SERVER_NAME,
        TLS_EXTENSION_MAX_FRAG_LEN,
        TLS_EXTENSION_STATUS_REQUEST,
        TLS_EXTENSION_SUPPORTED_GROUPS,
        TLS_EXTENSION_EC_POINT_FORMATS,
        TLS_EXTENSION_SIGNATURE_ALGORITHMS,
        TLS_EXTENSION_ALPN,
        TLS_EXTENSION_SCT_LIST,
        TLS_EXTENSION_SESSION_TICKET,
        TLS_EXTENSION_SUPPORTED_VERSIONS,
        TLS_EXTENSION_PQ_KEM_PARAMETERS,
        TLS_EXTENSION_RENEGOTIATION_INFO,
        TLS_EXTENSION_KEY_SHARE,
    };
    static const uint16_t  num_extensions = sizeof(extensions) / sizeof(uint16_t);
    for (uint16_t i = 0; i < num_extensions; i++) {
        s2n_register_extension(extensions[i]);
    }

    if (getenv("S2N_PRINT_STACKTRACE")) {
      s2n_stack_traces_enabled_set(true);
    }

    return 0;
}

int s2n_cleanup(void)
{
    /* s2n_cleanup is supposed to be called from each thread before exiting,
     * so ensure that whatever clean ups we have here are thread safe */
    GUARD(s2n_rand_cleanup_thread());
    return 0;
}

static void s2n_cleanup_atexit(void)
{
    s2n_rand_cleanup_thread();
    s2n_rand_cleanup();
    s2n_mem_cleanup();
    s2n_wipe_static_configs();
}

