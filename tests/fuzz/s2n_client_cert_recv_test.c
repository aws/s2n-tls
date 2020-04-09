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

/* Target Functions: s2n_client_cert_recv s2n_x509_validator_validate_cert_chain */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

struct host_verify_data {
    const char *name;
    uint8_t found_name;
    uint8_t callback_invoked;
};

static uint8_t verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data)
{
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 1;
}

static const uint8_t TLS_VERSIONS[] = {S2N_TLS10, S2N_TLS11, S2N_TLS12, S2N_TLS13};

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
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    /* We need at least one byte of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 1);

    /* Setup */
    struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
    struct s2n_x509_trust_store trust_store;
    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    notnull_check(server_conn);
    GUARD(s2n_stuffer_write_bytes(&server_conn->handshake.io, buf, len));

    /* Returns void, so can't be guarded */
    s2n_x509_trust_store_init_empty(&trust_store);

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    GUARD(s2n_stuffer_read_uint8(&server_conn->handshake.io, &randval));

    if(randval % 2) {
        GUARD(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        GUARD(s2n_connection_set_verify_host_callback(server_conn, verify_host_accept_everything, &verify_data));
    }

    GUARD(s2n_x509_validator_init(&server_conn->x509_validator, &trust_store, 1));
    server_conn->x509_validator.skip_cert_validation = (randval >> 1) % 2;
    server_conn->actual_protocol_version = TLS_VERSIONS[((randval >> 4) & 0x0f) % s2n_array_len(TLS_VERSIONS)];

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_client_cert_recv(server_conn);

    /* Cleanup */

    /* Returns void, so can't be guarded */
    s2n_x509_trust_store_wipe(&trust_store);
    s2n_x509_validator_wipe(&server_conn->x509_validator);

    GUARD(s2n_connection_free(server_conn));

    return 0;
}
