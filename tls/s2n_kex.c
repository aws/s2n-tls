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

#include "tls/s2n_kex.h"

#include "crypto/s2n_pq.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_server_key_exchange.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

static S2N_RESULT s2n_check_tls13(const struct s2n_cipher_suite *cipher_suite,
        struct s2n_connection *conn, bool *is_supported)
{
    RESULT_ENSURE_REF(is_supported);
    *is_supported = (s2n_connection_get_protocol_version(conn) >= S2N_TLS13);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_check_rsa_key(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn, bool *is_supported)
{
    RESULT_ENSURE_REF(cipher_suite);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(is_supported);

    *is_supported = s2n_get_compatible_cert_chain_and_key(conn, S2N_PKEY_TYPE_RSA) != NULL;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_check_dhe(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn, bool *is_supported)
{
    RESULT_ENSURE_REF(cipher_suite);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);
    RESULT_ENSURE_REF(is_supported);

    *is_supported = conn->config->dhparams != NULL;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_check_ecdhe(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn, bool *is_supported)
{
    RESULT_ENSURE_REF(cipher_suite);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(is_supported);

    *is_supported = conn->kex_params.server_ecc_evp_params.negotiated_curve != NULL;

    return S2N_RESULT_OK;
}

static int s2n_kex_server_key_recv_read_data_unimplemented(struct s2n_connection *conn,
        struct s2n_blob *data_to_verify, struct s2n_kex_raw_server_data *kex_data)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_kex_server_key_recv_parse_data_unimplemented(struct s2n_connection *conn,
        struct s2n_kex_raw_server_data *kex_data)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_kex_io_unimplemented(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_kex_prf_unimplemented(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

const struct s2n_kex s2n_rsa = {
    .is_ephemeral = false,
    .connection_supported = &s2n_check_rsa_key,
    .server_key_recv_read_data = &s2n_kex_server_key_recv_read_data_unimplemented,
    .server_key_recv_parse_data = &s2n_kex_server_key_recv_parse_data_unimplemented,
    .server_key_send = &s2n_kex_io_unimplemented,
    .client_key_recv = &s2n_rsa_client_key_recv,
    .client_key_send = &s2n_rsa_client_key_send,
    .prf = &s2n_prf_calculate_master_secret,
};

const struct s2n_kex s2n_dhe = {
    .is_ephemeral = true,
    .connection_supported = &s2n_check_dhe,
    .server_key_recv_read_data = &s2n_dhe_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_dhe_server_key_recv_parse_data,
    .server_key_send = &s2n_dhe_server_key_send,
    .client_key_recv = &s2n_dhe_client_key_recv,
    .client_key_send = &s2n_dhe_client_key_send,
    .prf = &s2n_prf_calculate_master_secret,
};

const struct s2n_kex s2n_ecdhe = {
    .is_ephemeral = true,
    .connection_supported = &s2n_check_ecdhe,
    .server_key_recv_read_data = &s2n_ecdhe_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_ecdhe_server_key_recv_parse_data,
    .server_key_send = &s2n_ecdhe_server_key_send,
    .client_key_recv = &s2n_ecdhe_client_key_recv,
    .client_key_send = &s2n_ecdhe_client_key_send,
    .prf = &s2n_prf_calculate_master_secret,
};

/* TLS1.3 key exchange is implemented differently from previous versions and does
 * not currently require most of the functionality offered by s2n_kex.
 * This structure primarily acts as a placeholder, so its methods are either
 * noops or unimplemented.
 */
const struct s2n_kex s2n_tls13_kex = {
    .is_ephemeral = true,
    .connection_supported = &s2n_check_tls13,
    .server_key_recv_read_data = &s2n_kex_server_key_recv_read_data_unimplemented,
    .server_key_recv_parse_data = &s2n_kex_server_key_recv_parse_data_unimplemented,
    .server_key_send = &s2n_kex_io_unimplemented,
    .client_key_recv = &s2n_kex_io_unimplemented,
    .client_key_send = &s2n_kex_io_unimplemented,
    .prf = &s2n_kex_prf_unimplemented,
};

S2N_RESULT s2n_kex_supported(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn, bool *is_supported)
{
    RESULT_ENSURE_REF(cipher_suite);
    RESULT_ENSURE_REF(cipher_suite->key_exchange_alg);
    RESULT_ENSURE_REF(cipher_suite->key_exchange_alg->connection_supported);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(is_supported);

    RESULT_GUARD(cipher_suite->key_exchange_alg->connection_supported(cipher_suite, conn, is_supported));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_is_ephemeral(const struct s2n_kex *kex, bool *is_ephemeral)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(is_ephemeral);

    *is_ephemeral = kex->is_ephemeral;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_server_key_recv_parse_data(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_kex_raw_server_data *raw_server_data)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(kex->server_key_recv_parse_data);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(raw_server_data);

    RESULT_GUARD_POSIX(kex->server_key_recv_parse_data(conn, raw_server_data));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_server_key_recv_read_data(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_verify,
        struct s2n_kex_raw_server_data *raw_server_data)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(kex->server_key_recv_read_data);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(data_to_verify);

    RESULT_GUARD_POSIX(kex->server_key_recv_read_data(conn, data_to_verify, raw_server_data));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_server_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(kex->server_key_send);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(data_to_sign);

    RESULT_GUARD_POSIX(kex->server_key_send(conn, data_to_sign));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(kex->client_key_recv);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(shared_key);

    RESULT_GUARD_POSIX(kex->client_key_recv(conn, shared_key));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(kex->client_key_send);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(shared_key);

    RESULT_GUARD_POSIX(kex->client_key_send(conn, shared_key));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_kex_tls_prf(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    RESULT_ENSURE_REF(kex);
    RESULT_ENSURE_REF(kex->prf);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(premaster_secret);

    RESULT_GUARD_POSIX(kex->prf(conn, premaster_secret));

    return S2N_RESULT_OK;
}

bool s2n_kex_includes(const struct s2n_kex *kex, const struct s2n_kex *query)
{
    if (kex == query) {
        return true;
    }

    if (kex == NULL || query == NULL) {
        return false;
    }

    return false;
}
