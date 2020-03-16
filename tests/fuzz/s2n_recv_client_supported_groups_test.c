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

/* Target Functions: s2n_recv_client_supported_groups s2n_ecc_evp_find_supported_curve */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "tls/extensions/s2n_client_supported_groups.h"

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls13.h"

/* This test is for TLS versions 1.3 and up only */
static const uint8_t TLS_VERSIONS[] = {S2N_TLS13};

static void s2n_fuzz_atexit()
{
    s2n_cleanup();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
#ifdef S2N_TEST_IN_FIPS_MODE
    S2N_TEST_ENTER_FIPS_MODE();
#endif

    GUARD(s2n_init());
    GUARD_STRICT(atexit(s2n_fuzz_atexit));
    GUARD(s2n_enable_tls13());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    /* We need at least one byte of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 1);

    /* Setup */
    struct s2n_stuffer fuzz_stuffer = {0};
    GUARD(s2n_stuffer_alloc(&fuzz_stuffer, len + 1));
    GUARD(s2n_stuffer_write_bytes(&fuzz_stuffer, buf, len));

    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    notnull_check(server_conn);

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    GUARD(s2n_stuffer_read_uint8(&fuzz_stuffer, &randval));
    server_conn->actual_protocol_version = TLS_VERSIONS[(randval & 0x0F) % s2n_array_len(TLS_VERSIONS)];
    server_conn->server_protocol_version = TLS_VERSIONS[(randval >> 4) % s2n_array_len(TLS_VERSIONS)];

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_recv_client_supported_groups(server_conn, &fuzz_stuffer);

    /* Cleanup */
    GUARD(s2n_connection_free(server_conn));
    GUARD(s2n_stuffer_free(&fuzz_stuffer));

    return 0;
}
