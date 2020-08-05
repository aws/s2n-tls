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
#include "crypto/s2n_fips.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_server_key_exchange.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

static int s2n_check_rsa_key(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    return s2n_get_compatible_cert_chain_and_key(conn, S2N_PKEY_TYPE_RSA) != NULL;
}

static int s2n_check_dhe(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    return conn->config->dhparams != NULL;
}

static int s2n_check_ecdhe(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    return conn->secure.server_ecc_evp_params.negotiated_curve != NULL;
}

static int s2n_check_kem(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    notnull_check(conn);
    /* There is no support for PQ KEMs while in FIPS mode */
    if (s2n_is_in_fips_mode()) {
        return 0;
    }

    const struct s2n_kem_preferences *kem_preferences = NULL;
    GUARD(s2n_connection_get_kem_preferences(conn, &kem_preferences));
    notnull_check(kem_preferences);

    if (kem_preferences->kem_count == 0) {
        return 0;
    }

    const struct s2n_iana_to_kem *supported_params = NULL;
    /* If the cipher suite has no supported KEMs return false */
    if (s2n_cipher_suite_to_kem(cipher_suite->iana_value, &supported_params) != 0) {
        return 0;
    }
    if (supported_params->kem_count == 0) {
        return 0;
    }

    struct s2n_blob *client_kem_pref_list = &(conn->secure.client_pq_kem_extension);
    const struct s2n_kem *chosen_kem = NULL;
    if (client_kem_pref_list == NULL || client_kem_pref_list->data == NULL) {
        /* If the client did not send a PQ KEM extension, then the server can pick its preferred parameter */
        if (s2n_choose_kem_without_peer_pref_list(cipher_suite->iana_value, kem_preferences->kems,
                                                  kem_preferences->kem_count, &chosen_kem)
            != 0) {
            return 0;
        }
    } else {
        /* If the client did send a PQ KEM extension, then the server must find a mutually supported parameter. */
        if (s2n_choose_kem_with_peer_pref_list(cipher_suite->iana_value, client_kem_pref_list, kem_preferences->kems,
                                               kem_preferences->kem_count, &chosen_kem)
            != 0) {
            return 0;
        }
    }

    return chosen_kem != NULL;
}

static int s2n_configure_kem(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    notnull_check(conn);
    /* There is no support for PQ KEMs while in FIPS mode */
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    const struct s2n_kem_preferences *kem_preferences = NULL;
    GUARD(s2n_connection_get_kem_preferences(conn, &kem_preferences));
    notnull_check(kem_preferences);

    struct s2n_blob *proposed_kems = &(conn->secure.client_pq_kem_extension);
    const struct s2n_kem *chosen_kem = NULL;
    if (proposed_kems == NULL || proposed_kems->data == NULL) {
        /* If the client did not send a PQ KEM extension, then the server can pick its preferred parameter */
        GUARD(s2n_choose_kem_without_peer_pref_list(cipher_suite->iana_value, kem_preferences->kems,
                                                    kem_preferences->kem_count, &chosen_kem));
    } else {
        /* If the client did send a PQ KEM extension, then the server must find a mutually supported parameter. */
        GUARD(s2n_choose_kem_with_peer_pref_list(cipher_suite->iana_value, proposed_kems, kem_preferences->kems,
                                                 kem_preferences->kem_count, &chosen_kem));
    }

    conn->secure.kem_params.kem = chosen_kem;
    return 0;
}

static int s2n_no_op_configure(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    return 0;
}

static int s2n_check_hybrid_ecdhe_kem(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    return s2n_check_ecdhe(cipher_suite, conn) && s2n_check_kem(cipher_suite, conn);
}

const struct s2n_kex s2n_kem = {
    .is_ephemeral = 1,
    .connection_supported = &s2n_check_kem,
    .configure_connection = &s2n_configure_kem,
    .server_key_recv_read_data = &s2n_kem_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_kem_server_key_recv_parse_data,
    .server_key_send = &s2n_kem_server_key_send,
    .client_key_recv = &s2n_kem_client_key_recv,
    .client_key_send = &s2n_kem_client_key_send,
};

const struct s2n_kex s2n_rsa = {
    .is_ephemeral = 0,
    .connection_supported = &s2n_check_rsa_key,
    .configure_connection = &s2n_no_op_configure,
    .server_key_recv_read_data = NULL,
    .server_key_recv_parse_data = NULL,
    .server_key_send = NULL,
    .client_key_recv = &s2n_rsa_client_key_recv,
    .client_key_send = &s2n_rsa_client_key_send,
    .prf = &s2n_tls_prf_master_secret,
};

const struct s2n_kex s2n_dhe = {
    .is_ephemeral = 1,
    .connection_supported = &s2n_check_dhe,
    .configure_connection = &s2n_no_op_configure,
    .server_key_recv_read_data = &s2n_dhe_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_dhe_server_key_recv_parse_data,
    .server_key_send = &s2n_dhe_server_key_send,
    .client_key_recv = &s2n_dhe_client_key_recv,
    .client_key_send = &s2n_dhe_client_key_send,
    .prf = &s2n_tls_prf_master_secret,
};

const struct s2n_kex s2n_ecdhe = {
    .is_ephemeral = 1,
    .connection_supported = &s2n_check_ecdhe,
    .configure_connection = &s2n_no_op_configure,
    .server_key_recv_read_data = &s2n_ecdhe_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_ecdhe_server_key_recv_parse_data,
    .server_key_send = &s2n_ecdhe_server_key_send,
    .client_key_recv = &s2n_ecdhe_client_key_recv,
    .client_key_send = &s2n_ecdhe_client_key_send,
    .prf = &s2n_tls_prf_master_secret,
};

const struct s2n_kex s2n_hybrid_ecdhe_kem = {
    .is_ephemeral = 1,
    .hybrid = { &s2n_ecdhe, &s2n_kem },
    .connection_supported = &s2n_check_hybrid_ecdhe_kem,
    .configure_connection = &s2n_configure_kem,
    .server_key_recv_read_data = &s2n_hybrid_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_hybrid_server_key_recv_parse_data,
    .server_key_send = &s2n_hybrid_server_key_send,
    .client_key_recv = &s2n_hybrid_client_key_recv,
    .client_key_send = &s2n_hybrid_client_key_send,
    .prf = &s2n_hybrid_prf_master_secret,
};

int s2n_kex_supported(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    /* Don't return -1 from notnull_check because that might allow a improperly configured kex to be marked as "supported" */
    return cipher_suite->key_exchange_alg->connection_supported != NULL && cipher_suite->key_exchange_alg->connection_supported(cipher_suite, conn);
}

int s2n_configure_kex(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn)
{
    notnull_check(cipher_suite);
    notnull_check(cipher_suite->key_exchange_alg);
    notnull_check(cipher_suite->key_exchange_alg->configure_connection);
    return cipher_suite->key_exchange_alg->configure_connection(cipher_suite, conn);
}

int s2n_kex_is_ephemeral(const struct s2n_kex *kex)
{
    notnull_check(kex);
    return kex->is_ephemeral;
}

int s2n_kex_server_key_recv_parse_data(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_kex_raw_server_data *raw_server_data)
{
    notnull_check(kex);
    notnull_check(kex->server_key_recv_parse_data);
    return kex->server_key_recv_parse_data(conn, raw_server_data);
}

int s2n_kex_server_key_recv_read_data(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_verify, struct s2n_kex_raw_server_data *raw_server_data)
{
    notnull_check(kex);
    notnull_check(kex->server_key_recv_read_data);
    return kex->server_key_recv_read_data(conn, data_to_verify, raw_server_data);
}

int s2n_kex_server_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    notnull_check(kex);
    notnull_check(kex->server_key_send);
    return kex->server_key_send(conn, data_to_sign);
}

int s2n_kex_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    notnull_check(kex);
    notnull_check(kex->client_key_recv);
    return kex->client_key_recv(conn, shared_key);
}

int s2n_kex_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    notnull_check(kex);
    notnull_check(kex->client_key_send);
    return kex->client_key_send(conn, shared_key);
}

int s2n_kex_tls_prf(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    notnull_check(kex);
    notnull_check(kex->prf);
    return kex->prf(conn, premaster_secret);
}

bool s2n_kex_includes(const struct s2n_kex *kex, const struct s2n_kex *query)
{
    if (kex == query) {
        return true;
    }

    if (kex == NULL || query == NULL) {
        return false;
    }

    return query == kex->hybrid[0] || query == kex->hybrid[1];
}
