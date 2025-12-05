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

#pragma once

#include "api/s2n.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

/* Destroy the server and client keys for a connection */
static int s2n_aead_test_destroy_keys(struct s2n_connection *conn)
{
    POSIX_GUARD_RESULT(conn->initial->cipher_suite->record_alg->cipher->destroy_key(&conn->initial->server_key));
    POSIX_GUARD_RESULT(conn->initial->cipher_suite->record_alg->cipher->destroy_key(&conn->initial->client_key));
    return 0;
}

/* Initialize and set up server and client keys for a connection */
static int s2n_aead_test_setup_keys(struct s2n_connection *conn, struct s2n_blob *key)
{
    POSIX_GUARD_RESULT(conn->initial->cipher_suite->record_alg->cipher->init(&conn->initial->server_key));
    POSIX_GUARD_RESULT(conn->initial->cipher_suite->record_alg->cipher->init(&conn->initial->client_key));
    POSIX_GUARD_RESULT(conn->initial->cipher_suite->record_alg->cipher->set_encryption_key(&conn->initial->server_key, key));
    POSIX_GUARD_RESULT(conn->initial->cipher_suite->record_alg->cipher->set_decryption_key(&conn->initial->client_key, key));
    return 0;
}

/* Prepare a connection for testing with the specified record algorithm */
static int s2n_aead_test_prep_connection(struct s2n_connection *conn,
        const struct s2n_record_algorithm *record_alg,
        struct s2n_blob *key)
{
    POSIX_GUARD(s2n_connection_wipe(conn));
    conn->actual_protocol_version_established = 1;
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;
    conn->server = conn->initial;
    conn->client = conn->initial;
    conn->initial->cipher_suite->record_alg = record_alg;
    POSIX_GUARD(s2n_aead_test_destroy_keys(conn));
    POSIX_GUARD(s2n_aead_test_setup_keys(conn, key));
    return 0;
}
