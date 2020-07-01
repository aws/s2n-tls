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

/* Target Functions: s2n_cert_req_recv s2n_recv_client_cert_preferences
                     s2n_cert_type_to_pkey_type s2n_recv_supported_sig_scheme_list
                     s2n_choose_sig_scheme_from_peer_preference_list
                     s2n_set_cert_chain_as_client */

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
#include "testlib/s2n_testlib.h"

static char *cert_chain, *private_key;
struct s2n_cert_chain_and_key *default_cert;

int s2n_fuzz_init(int *argc, char **argv[])
{
    /* Initialize test chain and key */
    cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE);
    notnull_check(cert_chain);
    private_key = malloc(S2N_MAX_TEST_PEM_SIZE);
    notnull_check(private_key);
    default_cert = s2n_cert_chain_and_key_new();
    notnull_check(default_cert);
    GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));

    return S2N_SUCCESS;
}

static const uint8_t TLS_VERSIONS[] = {S2N_TLS10, S2N_TLS11, S2N_TLS12};

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* We need at least one byte of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 1);

    /* Setup */
    struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
    notnull_check(client_conn);
    struct s2n_config *client_config = s2n_config_new();
    notnull_check(client_config);
    GUARD(s2n_config_add_cert_chain_and_key_to_store(client_config, default_cert));
    GUARD(s2n_connection_set_config(client_conn, client_config));
    GUARD(s2n_stuffer_write_bytes(&client_conn->handshake.io, buf, len));

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    GUARD(s2n_stuffer_read_uint8(&client_conn->handshake.io, &randval));
    client_conn->actual_protocol_version = TLS_VERSIONS[randval % s2n_array_len(TLS_VERSIONS)];

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_cert_req_recv(client_conn);

    /* Cleanup */
    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_config_free(client_config));

    return S2N_SUCCESS;
}

static void s2n_fuzz_cleanup()
{
    free(cert_chain);
    free(private_key);
    s2n_cert_chain_and_key_free(default_cert);
}

S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, s2n_fuzz_cleanup)
