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
                     s2n_kex_tls_prf s2n_prf_key_expansion s2n_ecdhe_client_key_recv
                     s2n_kem_client_key_recv s2n_hybrid_client_action */

#include "crypto/s2n_crypto.h"
#include "crypto/s2n_drbg.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "error/s2n_errno.h"
#include "pq-crypto/sike_r1/sike_r1_kem.h"
#include "stuffer/s2n_stuffer.h"
#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_ecc_preferences.h"

static struct s2n_kem_keypair server_kem_keys = {.negotiated_kem = &s2n_sike_p503_r1};

/* Setup the connection in a state for a fuzz test run, s2n_client_key_recv modifies the state of the connection
 * along the way and gets cleaned up at the end of each fuzz test.
 * - Connection needs cipher suite, curve, and kem setup
 * - Connection needs a ecdhe key and a kem private key, this would normally be setup when the server calls s2n_server_send_key
 * */
static int setup_connection(struct s2n_connection *server_conn)
{
    server_conn->actual_protocol_version = S2N_TLS12;
    const struct s2n_ecc_preferences *ecc_preferences = server_conn->config->ecc_preferences;
    server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
    server_conn->secure.server_ecc_evp_params.evp_pkey = NULL;
    server_conn->secure.s2n_kem_keys.negotiated_kem = &s2n_sike_p503_r1;
    server_conn->secure.cipher_suite = &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384;
    server_conn->secure.conn_sig_scheme = s2n_rsa_pkcs1_sha384;

    GUARD(s2n_dup(&server_kem_keys.private_key, &server_conn->secure.s2n_kem_keys.private_key));
    GUARD(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.server_ecc_evp_params));

    return 0;
}

static void s2n_fuzz_atexit()
{
    s2n_cleanup();
    s2n_kem_free(&server_kem_keys);
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
    GUARD(s2n_init());
    GUARD_STRICT(atexit(s2n_fuzz_atexit));

    struct s2n_blob *public_key = &server_kem_keys.public_key;
    GUARD(s2n_alloc(public_key, SIKE_P503_R1_PUBLIC_KEY_BYTES));
    GUARD(s2n_kem_generate_keypair(&server_kem_keys));
    GUARD(s2n_free(public_key));

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_connection *server_conn;
    notnull_check(server_conn = s2n_connection_new(S2N_SERVER));
    GUARD(setup_connection(server_conn));

    /* You can't write 0 bytes to a stuffer but attempting to call s2n_client_key_recv with 0 data is an interesting test */
    if (len > 0) {
        GUARD(s2n_stuffer_write_bytes(&server_conn->handshake.io, buf, len));
    }

    /* The missing GUARD is because s2n_client_key_recv might fail due to bad input which is okay, the connection
     * must still be cleaned up. Don't return s2n_client_key_recv's result because the the test still passes as long as
     * s2n_client_key_recv does not leak/contaminate any memory, the fuzz input is most likely not valid and will fail
     * to be recv'd successfully. */
    s2n_client_key_recv(server_conn);

    GUARD(s2n_connection_free(server_conn));

    return 0;
}
