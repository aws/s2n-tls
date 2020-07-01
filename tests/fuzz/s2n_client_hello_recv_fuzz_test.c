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

/* Target Functions: s2n_client_hello_recv s2n_parse_client_hello s2n_populate_client_hello_extensions
                     s2n_process_client_hello s2n_collect_client_hello */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "tls/s2n_tls13.h"

static const uint8_t TLS_VERSIONS[] = {S2N_TLS10, S2N_TLS11, S2N_TLS12, S2N_TLS13};

int s2n_fuzz_init(int *argc, char **argv[])
{
    GUARD(s2n_enable_tls13());
    srand(time(0));
    return S2N_SUCCESS;
}

/* Returns the value of ctx as an int when called */
int client_hello_cb_ret(struct s2n_connection *conn, void *ctx)
{
    return *((int*)ctx);
}

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* We need at least two bytes of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 2);

    /* Setup */
    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    notnull_check(server_conn);
    GUARD(s2n_stuffer_write_bytes(&server_conn->handshake.io, buf, len));

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    int ctxval = 0;
    GUARD(s2n_stuffer_read_uint8(&server_conn->handshake.io, &randval));
    server_conn->actual_protocol_version = TLS_VERSIONS[(randval & 0x0F) % s2n_array_len(TLS_VERSIONS)];
    server_conn->server_protocol_version = TLS_VERSIONS[(randval >> 4) % s2n_array_len(TLS_VERSIONS)];

    /* When callback function is called, return int chosen by libfuzzer between -1 and 1 to reach all code branches */
    GUARD(s2n_stuffer_read_uint8(&server_conn->handshake.io, &randval));
    ctxval = (int)(randval % 3) - 1;
    GUARD(s2n_config_set_client_hello_cb(server_conn->config, client_hello_cb_ret, &ctxval));

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_client_hello_recv(server_conn);

    /* Cleanup */
    GUARD(s2n_connection_free(server_conn));

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, NULL)
