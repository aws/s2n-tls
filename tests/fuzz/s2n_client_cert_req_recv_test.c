/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"

static void s2n_client_cert_req_recv_fuzz_atexit()
{
    s2n_cleanup();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
    GUARD(s2n_init());
    GUARD(atexit(s2n_client_cert_req_recv_fuzz_atexit));
    return 0;
}

static const uint8_t TLS_VERSIONS[] = {S2N_TLS10, S2N_TLS11, S2N_TLS12};

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    for(int i = 0; i < sizeof(TLS_VERSIONS); i++){
        /* Setup */
        struct s2n_config *client_config = s2n_config_new();
        s2n_config_disable_x509_verification(client_config);
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        notnull_check(client_conn);
        client_conn->actual_protocol_version = TLS_VERSIONS[i];
        s2n_connection_set_config(client_conn, client_config);
        GUARD(s2n_stuffer_write_bytes(&client_conn->handshake.io, buf, len));

        /* Run Test
         * Do not use GUARD macro here since the connection memory hasn't been freed.
         */
        s2n_client_cert_req_recv(client_conn);

        /* Cleanup */
        GUARD(s2n_connection_free(client_conn));
        GUARD(s2n_config_free(client_config));
    }

    return 0;
}
