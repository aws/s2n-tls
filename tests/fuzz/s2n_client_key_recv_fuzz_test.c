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

/* Target Functions: s2n_client_key_recv s2n_kex_client_key_recv calculate_keys
                     s2n_hybrid_client_action s2n_kex_tls_prf s2n_prf_key_expansion
                     s2n_rsa_client_key_recv s2n_dhe_client_key_recv
                     s2n_ecdhe_client_key_recv s2n_kem_client_key_recv */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "tls/s2n_kem.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_security_policies.h"

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

static const uint8_t TLS_VERSIONS[] = {S2N_TLS10, S2N_TLS11, S2N_TLS12};

/* Connection setup variables */
uint8_t *cert_chain_pem = NULL;
uint8_t *private_key_pem = NULL;
char *dhparams_pem = NULL;
uint32_t cert_chain_len = 0;
uint32_t private_key_len = 0;
struct s2n_config *config;
struct s2n_cert_chain_and_key *chain_and_key;
struct s2n_cert_chain_and_key *cert;
struct s2n_cipher_suite **test_suites;
int num_suites;

int s2n_fuzz_init(int *argc, char **argv[])
{
#ifdef S2N_TEST_IN_FIPS_MODE
    test_suites = cipher_preferences_test_all_fips.suites;
    num_suites = cipher_preferences_test_all_fips.count;
#else
    test_suites = cipher_preferences_test_all.suites;
    num_suites = cipher_preferences_test_all.count;
#endif

    /* One time Diffie-Hellman negotiation to speed along fuzz tests*/
    cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE);
    private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE);
    dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE);

    POSIX_ENSURE_REF(cert_chain_pem);
    POSIX_ENSURE_REF(private_key_pem);
    POSIX_ENSURE_REF(dhparams_pem);

    s2n_read_test_pem_and_len(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, &cert_chain_len, S2N_MAX_TEST_PEM_SIZE);
    s2n_read_test_pem_and_len(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, &private_key_len, S2N_MAX_TEST_PEM_SIZE);
    s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE);

    config = s2n_config_new();
    chain_and_key = s2n_cert_chain_and_key_new();

    POSIX_ENSURE_REF(config);
    POSIX_ENSURE_REF(chain_and_key);

    s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, cert_chain_pem, cert_chain_len, private_key_pem, private_key_len);
    s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key);
    s2n_config_add_dhparams(config, dhparams_pem);

    cert = s2n_config_get_single_default_cert(config);
    POSIX_ENSURE_REF(cert);

    return S2N_SUCCESS;
}

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* We need at least two bytes of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 2);

    /* Setup */
    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    POSIX_ENSURE_REF(server_conn);
    POSIX_GUARD(s2n_stuffer_write_bytes(&server_conn->handshake.io, buf, len));

    /* Read bytes from the libfuzzer input and use them to set parameters */
    uint8_t randval = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(&server_conn->handshake.io, &randval));
    server_conn->server_protocol_version = TLS_VERSIONS[randval % s2n_array_len(TLS_VERSIONS)];

    POSIX_GUARD(s2n_stuffer_read_uint8(&server_conn->handshake.io, &randval));
    server_conn->secure->cipher_suite = test_suites[randval % num_suites];

    /* Skip incompatible TLS 1.3 cipher suites */
    if (server_conn->secure->cipher_suite->key_exchange_alg == NULL) {
        POSIX_GUARD(s2n_connection_free(server_conn));
        return S2N_SUCCESS;
    }

    server_conn->handshake_params.our_chain_and_key = cert;

    const struct s2n_ecc_preferences *ecc_preferences = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(server_conn, &ecc_preferences));
    POSIX_ENSURE_REF(ecc_preferences);

    if (server_conn->secure->cipher_suite->key_exchange_alg->client_key_recv == s2n_ecdhe_client_key_recv || server_conn->secure->cipher_suite->key_exchange_alg->client_key_recv == s2n_hybrid_client_key_recv) {
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
        s2n_ecc_evp_generate_ephemeral_key(&server_conn->kex_params.server_ecc_evp_params);
    }

    if (server_conn->secure->cipher_suite->key_exchange_alg->client_key_recv == s2n_kem_client_key_recv || server_conn->secure->cipher_suite->key_exchange_alg->client_key_recv == s2n_hybrid_client_key_recv) {
        server_conn->kex_params.kem_params.kem = &s2n_kyber_512_r3;
    }

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_client_key_recv(server_conn);

    /* Cleanup */
    POSIX_GUARD(s2n_connection_free(server_conn));

    return S2N_SUCCESS;
}

static void s2n_fuzz_cleanup()
{
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);
    s2n_config_free(config);
    s2n_cert_chain_and_key_free(chain_and_key);
}

S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, s2n_fuzz_cleanup)
