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

/* Target Functions: s2n_tls13_cert_req_recv s2n_extension_list_recv s2n_extension_process
                     s2n_extension_list_process s2n_extension_parse s2n_extension_list_parse */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

static char *cert_chain, *private_key;
struct s2n_cert_chain_and_key *default_cert;
struct s2n_config *client_config;

int s2n_fuzz_init(int *argc, char **argv[])
{
    /* Initialize test chain and key */
    cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE);
    POSIX_ENSURE_REF(cert_chain);
    private_key = malloc(S2N_MAX_TEST_PEM_SIZE);
    POSIX_ENSURE_REF(private_key);
    default_cert = s2n_cert_chain_and_key_new();
    POSIX_ENSURE_REF(default_cert);
    client_config = s2n_config_new();
    POSIX_ENSURE_REF(client_config);
    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));
    POSIX_GUARD(s2n_config_add_cert_chain_and_key_to_store(client_config, default_cert));
    return S2N_SUCCESS;
}

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* Setup */
    struct s2n_connection *client_conn = s2n_connection_new(S2N_SERVER);
    POSIX_ENSURE_REF(client_conn);
    POSIX_GUARD(s2n_connection_set_config(client_conn, client_config));
    POSIX_GUARD(s2n_stuffer_write_bytes(&client_conn->handshake.io, buf, len));

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_tls13_cert_req_recv(client_conn);

    /* Cleanup */
    POSIX_GUARD(s2n_connection_free(client_conn));

    return S2N_SUCCESS;
}

static void s2n_fuzz_cleanup()
{
    s2n_config_free(client_config);
    free(cert_chain);
    free(private_key);
    s2n_cert_chain_and_key_free(default_cert);
}

S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, s2n_fuzz_cleanup)
