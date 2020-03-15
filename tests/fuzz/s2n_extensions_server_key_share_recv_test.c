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

/* Target Functions: s2n_extensions_server_key_share_recv s2n_ecc_evp_read_params_point s2n_ecc_evp_parse_params_point */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_ecc_preferences.h"

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls13.h"
#include "crypto/s2n_ecc_evp.h"

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
    GUARD(s2n_stuffer_alloc(&fuzz_stuffer, len));
    GUARD(s2n_stuffer_write_bytes(&fuzz_stuffer, buf, len));

    struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
    EXPECT_NOT_NULL(client_conn);

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    GUARD(s2n_stuffer_read_uint8(&fuzz_stuffer, &randval));
    client_conn->actual_protocol_version = TLS_VERSIONS[randval % s2n_array_len(TLS_VERSIONS)];

    EXPECT_NOT_NULL(client_conn->config);
    const struct s2n_ecc_preferences *ecc_preferences = client_conn->config->ecc_preferences;
    EXPECT_NOT_NULL(ecc_preferences);
    
    /* Generate ephemeral keys for all supported curves */
    for (int i = 0; i < ecc_preferences->count; i++) {
        client_conn->secure.client_ecc_evp_params[i].negotiated_curve = ecc_preferences->ecc_curves[i];
        GUARD(s2n_ecc_evp_generate_ephemeral_key(&client_conn->secure.client_ecc_evp_params[i]));
    }

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_extensions_server_key_share_recv(client_conn, &fuzz_stuffer);

    /* Cleanup */
    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_stuffer_free(&fuzz_stuffer));

    return 0;
}
