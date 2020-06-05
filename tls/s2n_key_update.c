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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_record.h"

#include "crypto/s2n_sequence.h"

#include "utils/s2n_safety.h"

int s2n_key_update_write(struct s2n_blob *out);
int s2n_check_record_limit(struct s2n_connection *conn, struct s2n_blob *sequence_number); 


int s2n_key_update_recv(struct s2n_connection *conn, struct s2n_stuffer *request)
{
    notnull_check(conn);

    uint8_t key_update_request;
    GUARD(s2n_stuffer_read_uint8(request, &key_update_request));
    S2N_ERROR_IF(key_update_request != S2N_KEY_UPDATE_NOT_REQUESTED && key_update_request != S2N_KEY_UPDATE_REQUESTED,
            S2N_ERR_BAD_MESSAGE);
    conn->key_update_pending = key_update_request;

    /* Update peer's key since a key_update was received */
    if (conn->mode == S2N_CLIENT){
        GUARD(s2n_update_application_traffic_keys(conn, S2N_SERVER, RECEIVING));
    } else {
        GUARD(s2n_update_application_traffic_keys(conn, S2N_CLIENT, RECEIVING));
    }

    return S2N_SUCCESS;
}

int s2n_key_update_send(struct s2n_connection *conn) 
{
    notnull_check(conn);

    struct s2n_blob sequence_number = {0};
    if (conn->mode == S2N_CLIENT) {
        GUARD(s2n_blob_init(&sequence_number, conn->secure.client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
    } else {
        GUARD(s2n_blob_init(&sequence_number, conn->secure.server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
    }

    GUARD(s2n_check_record_limit(conn, &sequence_number));

    if (conn->key_update_pending) {
        uint8_t key_update_data[S2N_KEY_UPDATE_MESSAGE_SIZE];
        struct s2n_blob key_update_blob = {0};
        GUARD(s2n_blob_init(&key_update_blob, key_update_data, sizeof(key_update_data)));

        /* Write key update message */
        GUARD(s2n_key_update_write(&key_update_blob));

        /* Encrypt the message */
        GUARD(s2n_record_write(conn, TLS_HANDSHAKE,  &key_update_blob));

        /* Update encryption key */
        GUARD(s2n_update_application_traffic_keys(conn, conn->mode, SENDING));
        conn->key_update_pending = false;
    }

    return S2N_SUCCESS;
}

int s2n_key_update_write(struct s2n_blob *out)
{
    notnull_check(out);

    struct s2n_stuffer key_update_stuffer = {0};
    GUARD(s2n_stuffer_init(&key_update_stuffer, out));
    GUARD(s2n_stuffer_write_uint8(&key_update_stuffer, TLS_KEY_UPDATE));
    GUARD(s2n_stuffer_write_uint24(&key_update_stuffer, S2N_KEY_UPDATE_LENGTH));

    /* s2n currently does not require peers to update their encryption keys. */
    GUARD(s2n_stuffer_write_uint8(&key_update_stuffer, S2N_KEY_UPDATE_NOT_REQUESTED));

    return S2N_SUCCESS;
}

int s2n_check_record_limit(struct s2n_connection *conn, struct s2n_blob *sequence_number)
{
    notnull_check(conn);
    notnull_check(sequence_number);
    notnull_check(conn->secure.cipher_suite);
    notnull_check(conn->secure.cipher_suite->record_alg);

    uint64_t output = 0;
    GUARD(s2n_sequence_number_to_uint64(sequence_number, &output));

    if (output + 1 > conn->secure.cipher_suite->record_alg->encryption_limit) {
        conn->key_update_pending = true;
    }

    return S2N_SUCCESS;
}

