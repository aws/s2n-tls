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

#include "tls/s2n_early_data.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_psk.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

const s2n_early_data_state valid_previous_states[] = {
        [S2N_EARLY_DATA_REQUESTED]      = S2N_UNKNOWN_EARLY_DATA_STATE,
        [S2N_EARLY_DATA_NOT_REQUESTED]  = S2N_UNKNOWN_EARLY_DATA_STATE,
        [S2N_EARLY_DATA_REJECTED]       = S2N_EARLY_DATA_REQUESTED,
        [S2N_EARLY_DATA_ACCEPTED]       = S2N_EARLY_DATA_REQUESTED,
        [S2N_END_OF_EARLY_DATA]         = S2N_EARLY_DATA_ACCEPTED,
};

S2N_RESULT s2n_connection_set_early_data_state(struct s2n_connection *conn, s2n_early_data_state next_state)
{
    ENSURE_REF(conn);
    ENSURE(next_state < S2N_EARLY_DATA_STATES_COUNT, S2N_ERR_INVALID_EARLY_DATA_STATE);
    ENSURE(next_state != S2N_UNKNOWN_EARLY_DATA_STATE, S2N_ERR_INVALID_EARLY_DATA_STATE);
    ENSURE(conn->early_data_state == valid_previous_states[next_state], S2N_ERR_INVALID_EARLY_DATA_STATE);
    conn->early_data_state = next_state;
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_early_data_config_free(struct s2n_early_data_config *config)
{
    if (config == NULL) {
        return S2N_RESULT_OK;
    }
    GUARD_AS_RESULT(s2n_free(&config->application_protocol));
    GUARD_AS_RESULT(s2n_free(&config->context));
    return S2N_RESULT_OK;
}

int s2n_psk_configure_early_data(struct s2n_psk *psk, uint32_t max_early_data_size,
        uint8_t cipher_suite_first_byte, uint8_t cipher_suite_second_byte)
{
    notnull_check(psk);

    const uint8_t cipher_suite_iana[] = { cipher_suite_first_byte, cipher_suite_second_byte };
    struct s2n_cipher_suite *cipher_suite = NULL;
    GUARD_AS_POSIX(s2n_cipher_suite_from_iana(cipher_suite_iana, &cipher_suite));
    notnull_check(cipher_suite);
    ENSURE_POSIX(cipher_suite->prf_alg == psk->hmac_alg, S2N_ERR_INVALID_ARGUMENT);

    psk->early_data_config.max_early_data_size = max_early_data_size;
    psk->early_data_config.protocol_version = S2N_TLS13;
    psk->early_data_config.cipher_suite = cipher_suite;
    return S2N_SUCCESS;
}

int s2n_psk_set_application_protocol(struct s2n_psk *psk, const uint8_t *application_protocol, uint8_t size)
{
    notnull_check(psk);
    if (size > 0) {
        notnull_check(application_protocol);
    }
    struct s2n_blob *protocol_blob = &psk->early_data_config.application_protocol;
    GUARD(s2n_realloc(protocol_blob, size));
    memcpy_check(protocol_blob->data, application_protocol, size);
    return S2N_SUCCESS;
}

int s2n_psk_set_context(struct s2n_psk *psk, const uint8_t *context, uint16_t size)
{
    notnull_check(psk);
    if (size > 0) {
        notnull_check(context);
    }
    struct s2n_blob *context_blob = &psk->early_data_config.context;
    GUARD(s2n_realloc(context_blob, size));
    memcpy_check(context_blob->data, context, size);
    return S2N_SUCCESS;
}

S2N_RESULT s2n_early_data_config_clone(struct s2n_psk *new_psk, struct s2n_early_data_config *old_config)
{
    ENSURE_REF(old_config);
    ENSURE_REF(new_psk);

    struct s2n_early_data_config config_copy = new_psk->early_data_config;

    /* Copy all fields from the old_config EXCEPT the blobs, which we need to reallocate. */
    new_psk->early_data_config = *old_config;
    new_psk->early_data_config.application_protocol = config_copy.application_protocol;
    new_psk->early_data_config.context = config_copy.context;

    /* Clone / realloc blobs */
    GUARD_AS_RESULT(s2n_psk_set_application_protocol(new_psk, old_config->application_protocol.data,
            old_config->application_protocol.size));
    GUARD_AS_RESULT(s2n_psk_set_context(new_psk, old_config->context.data,
            old_config->context.size));

    return S2N_RESULT_OK;
}
