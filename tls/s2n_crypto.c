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

#include "tls/s2n_crypto.h"

#include "api/s2n.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_crypto_parameters_new(struct s2n_crypto_parameters **new_params)
{
    RESULT_ENSURE_REF(new_params);
    RESULT_ENSURE_EQ(*new_params, NULL);

    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_crypto_parameters)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&mem));

    DEFER_CLEANUP(struct s2n_crypto_parameters *params = (struct s2n_crypto_parameters *) (void *) mem.data,
            s2n_crypto_parameters_free);
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);

    /* Allocate long-term memory for the HMAC states */
    RESULT_GUARD_POSIX(s2n_hmac_new(&params->client_record_mac));
    RESULT_GUARD_POSIX(s2n_hmac_new(&params->server_record_mac));

    /* Allocate key memory */
    RESULT_GUARD_POSIX(s2n_session_key_alloc(&params->client_key));
    RESULT_GUARD_POSIX(s2n_session_key_alloc(&params->server_key));

    /* Setup */
    RESULT_GUARD(s2n_crypto_parameters_wipe(params));

    *new_params = params;
    ZERO_TO_DISABLE_DEFER_CLEANUP(params);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_crypto_parameters_wipe(struct s2n_crypto_parameters *params)
{
    RESULT_ENSURE_REF(params);

    /* Wipe the hmacs for reuse */
    struct s2n_hmac_state client_state = params->client_record_mac;
    struct s2n_hmac_state server_state = params->server_record_mac;
    RESULT_GUARD_POSIX(s2n_hmac_init(&client_state, S2N_HMAC_NONE, NULL, 0));
    RESULT_GUARD_POSIX(s2n_hmac_init(&server_state, S2N_HMAC_NONE, NULL, 0));

    /* Wipe the keys for reuse */
    struct s2n_session_key client_key = params->client_key;
    struct s2n_session_key server_key = params->server_key;
    if (params->cipher_suite
            && params->cipher_suite->record_alg
            && params->cipher_suite->record_alg->cipher
            && params->cipher_suite->record_alg->cipher->destroy_key) {
        RESULT_GUARD_POSIX(params->cipher_suite->record_alg->cipher->destroy_key(&params->client_key));
        RESULT_GUARD_POSIX(params->cipher_suite->record_alg->cipher->destroy_key(&params->server_key));
    }

    *params = (struct s2n_crypto_parameters){ 0 };

    params->client_record_mac = client_state;
    params->server_record_mac = server_state;
    params->client_key = client_key;
    params->server_key = server_key;
    params->cipher_suite = &s2n_null_cipher_suite;
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_crypto_parameters_free(struct s2n_crypto_parameters **params)
{
    if (params == NULL || *params == NULL) {
        return S2N_RESULT_OK;
    }

    /* Free HMAC states */
    RESULT_GUARD_POSIX(s2n_hmac_free(&(*params)->client_record_mac));
    RESULT_GUARD_POSIX(s2n_hmac_free(&(*params)->server_record_mac));

    /* Free session keys */
    RESULT_GUARD_POSIX(s2n_session_key_free(&(*params)->client_key));
    RESULT_GUARD_POSIX(s2n_session_key_free(&(*params)->server_key));

    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) params, sizeof(struct s2n_crypto_parameters)));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_crypto_parameters_switch(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->initial);

    /* Only start encryption if we have not already switched to secure parameters */
    if (conn->mode == S2N_CLIENT && conn->client == conn->initial) {
        struct s2n_blob seq = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&seq, conn->secure->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
        RESULT_GUARD_POSIX(s2n_blob_zero(&seq));
        conn->client = conn->secure;
    } else if (conn->mode == S2N_SERVER && conn->server == conn->initial) {
        struct s2n_blob seq = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&seq, conn->secure->server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
        RESULT_GUARD_POSIX(s2n_blob_zero(&seq));
        conn->server = conn->secure;
    }

    return S2N_RESULT_OK;
}
