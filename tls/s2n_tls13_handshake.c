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

#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_ecc_preferences.h"

int s2n_tls13_mac_verify(struct s2n_tls13_keys *keys, struct s2n_blob *finished_verify, struct s2n_blob *wire_verify)
{
    notnull_check(wire_verify->data);
    eq_check(wire_verify->size, keys->size);

    S2N_ERROR_IF(!s2n_constant_time_equals(finished_verify->data, wire_verify->data, keys->size), S2N_ERR_BAD_MESSAGE);

    return 0;
}

/*
 * Initalizes the tls13_keys struct
 */
static int s2n_tls13_keys_init_with_ref(struct s2n_tls13_keys *handshake, s2n_hmac_algorithm alg, uint8_t * extract,  uint8_t * derive)
{
    notnull_check(handshake);

    handshake->hmac_algorithm = alg;
    GUARD(s2n_hmac_hash_alg(alg, &handshake->hash_algorithm));
    GUARD(s2n_hash_digest_size(handshake->hash_algorithm, &handshake->size));
    GUARD(s2n_blob_init(&handshake->extract_secret, extract, handshake->size));
    GUARD(s2n_blob_init(&handshake->derive_secret, derive, handshake->size));
    GUARD(s2n_hmac_new(&handshake->hmac));

    return 0;
}

int s2n_tls13_keys_from_conn(struct s2n_tls13_keys *keys, struct s2n_connection *conn)
{
    GUARD(s2n_tls13_keys_init_with_ref(keys, conn->secure.cipher_suite->prf_alg, conn->secure.rsa_premaster_secret, conn->secure.master_secret));

    return 0;
}

int s2n_tls13_compute_shared_secret(struct s2n_connection *conn, struct s2n_blob *shared_secret)
{
    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_preferences = conn->config->ecc_preferences;
    notnull_check(ecc_preferences);
    struct s2n_ecc_evp_params *server_key = &conn->secure.server_ecc_evp_params;
    notnull_check(server_key);

    /* for now we do this tedious loop to find the matching client key selection.
     * this can be simplified if we get an index or a pointer to a specific key */
    int selection = -1;
    for (int i = 0; i < ecc_preferences->count; i++) {
        if (server_key->negotiated_curve->iana_id == ecc_preferences->ecc_curves[i]->iana_id) {
            selection = i;
            break;
        }
    }

    S2N_ERROR_IF(selection < 0, S2N_ERR_BAD_KEY_SHARE);
    struct s2n_ecc_evp_params *client_key = &conn->secure.client_ecc_evp_params[selection];
    notnull_check(client_key);

    if (conn->mode == S2N_CLIENT) {
        GUARD(s2n_ecc_evp_compute_shared_secret_from_params(client_key, server_key, shared_secret));
    } else {
        GUARD(s2n_ecc_evp_compute_shared_secret_from_params(server_key, client_key, shared_secret));
    }

    return 0;
}

/*
 * This function executes after Server Hello is processed
 * and handshake hashes are computed. It produces and configure
 * the shared secret, handshake secrets, handshake traffic keys,
 * and finished keys.
 */
int s2n_tls13_handle_handshake_secrets(struct s2n_connection *conn)
{
    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_preferences = conn->config->ecc_preferences;
    notnull_check(ecc_preferences);
    
    /* get tls13 key context */
    s2n_tls13_connection_keys(secrets, conn);

    /* get shared secret */
    DEFER_CLEANUP(struct s2n_blob shared_secret = { 0 }, s2n_free);
    GUARD(s2n_tls13_compute_shared_secret(conn, &shared_secret));

    /* derive early secrets */
    GUARD(s2n_tls13_derive_early_secrets(&secrets));

    /* produce handshake secrets */
    s2n_stack_blob(client_hs_secret, secrets.size, S2N_TLS13_SECRET_MAX_LEN);
    s2n_stack_blob(server_hs_secret, secrets.size, S2N_TLS13_SECRET_MAX_LEN);

    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, secrets.hash_algorithm, &hash_state));
    GUARD(s2n_tls13_derive_handshake_secrets(&secrets, &shared_secret, &hash_state, &client_hs_secret, &server_hs_secret));

    /* produce handshake traffic keys and configure record algorithm */
    s2n_tls13_key_blob(server_hs_key, conn->secure.cipher_suite->record_alg->cipher->key_material_size);
    struct s2n_blob server_hs_iv = { .data = conn->secure.server_implicit_iv, .size = S2N_TLS13_FIXED_IV_LEN };
    GUARD(s2n_tls13_derive_traffic_keys(&secrets, &server_hs_secret, &server_hs_key, &server_hs_iv));

    s2n_tls13_key_blob(client_hs_key, conn->secure.cipher_suite->record_alg->cipher->key_material_size);
    struct s2n_blob client_hs_iv = { .data = conn->secure.client_implicit_iv, .size = S2N_TLS13_FIXED_IV_LEN };
    GUARD(s2n_tls13_derive_traffic_keys(&secrets, &client_hs_secret, &client_hs_key, &client_hs_iv));

    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));

    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.server_key, &server_hs_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.client_key, &client_hs_key));

    /* calculate server + client finished keys and store them in handshake struct */
    struct s2n_blob server_finished_key = { .data = conn->handshake.server_finished, .size = secrets.size };
    struct s2n_blob client_finished_key = { .data = conn->handshake.client_finished, .size = secrets.size };
    GUARD(s2n_tls13_derive_finished_key(&secrets, &server_hs_secret, &server_finished_key));
    GUARD(s2n_tls13_derive_finished_key(&secrets, &client_hs_secret, &client_finished_key));

    /* since shared secret has been computed, clean up keys */
    GUARD(s2n_ecc_evp_params_free(&conn->secure.server_ecc_evp_params));
    for (int i = 0; i < ecc_preferences->count; i++) {
        GUARD(s2n_ecc_evp_params_free(&conn->secure.client_ecc_evp_params[i]));
    }

    return 0;
}

/*
 * This must be called after ServerFinished
 */
int s2n_tls13_handle_application_secrets(struct s2n_connection *conn)
{
    /* get tls13 key context */
    s2n_tls13_connection_keys(keys, conn);

    /* produce application secrets */
    s2n_stack_blob(client_app_secret, keys.size, S2N_TLS13_SECRET_MAX_LEN);
    s2n_stack_blob(server_app_secret, keys.size, S2N_TLS13_SECRET_MAX_LEN);

    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));
    GUARD(s2n_tls13_derive_application_secrets(&keys, &hash_state, &client_app_secret, &server_app_secret));

    s2n_tls13_key_blob(s_app_key, conn->secure.cipher_suite->record_alg->cipher->key_material_size);
    struct s2n_blob s_app_iv = { .data = conn->secure.server_implicit_iv, .size = S2N_TLS13_FIXED_IV_LEN };
    GUARD(s2n_tls13_derive_traffic_keys(&keys, &server_app_secret, &s_app_key, &s_app_iv));

    s2n_tls13_key_blob(c_app_key, conn->secure.cipher_suite->record_alg->cipher->key_material_size);
    struct s2n_blob c_app_iv = { .data = conn->secure.client_implicit_iv, .size = S2N_TLS13_FIXED_IV_LEN };
    GUARD(s2n_tls13_derive_traffic_keys(&keys, &client_app_secret, &c_app_key, &c_app_iv));

    /* update record algorithm secrets */
    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.server_key, &s_app_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.client_key, &c_app_key));

    return 0;
}
