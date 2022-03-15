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

#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_connection_set_test_transcript_hash(struct s2n_connection *conn,
        message_type_t message_type, const struct s2n_blob *digest)
{
    conn->handshake.handshake_type = conn->handshake.handshake_type & NEGOTIATED;
    while(s2n_conn_get_current_message_type(conn) != message_type) {
        conn->handshake.message_number++;
    }
    RESULT_CHECKED_MEMCPY(conn->handshake.hashes->transcript_hash_digest,
            digest->data, digest->size);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_connection_set_test_early_secret(struct s2n_connection *conn,
        const struct s2n_blob *early_secret)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(early_secret);
    RESULT_CHECKED_MEMCPY(conn->secrets.tls13.extract_secret,
            early_secret->data, early_secret->size);
    conn->secrets.tls13.extract_secret_type = S2N_EARLY_SECRET;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_connection_set_test_handshake_secret(struct s2n_connection *conn,
        const struct s2n_blob *handshake_secret)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(handshake_secret);
    RESULT_CHECKED_MEMCPY(conn->secrets.tls13.extract_secret,
            handshake_secret->data, handshake_secret->size);
    conn->secrets.tls13.extract_secret_type = S2N_HANDSHAKE_SECRET;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_connection_set_test_master_secret(struct s2n_connection *conn,
        const struct s2n_blob *master_secret)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(master_secret);
    RESULT_CHECKED_MEMCPY(conn->secrets.tls13.extract_secret,
            master_secret->data, master_secret->size);
    conn->secrets.tls13.extract_secret_type = S2N_MASTER_SECRET;
    return S2N_RESULT_OK;
}
