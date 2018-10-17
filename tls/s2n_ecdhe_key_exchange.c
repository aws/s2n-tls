/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_ecc.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_kem_core.h"
#include "tls/s2n_tls_digest_preferences.h"

#include "utils/s2n_safety.h"
#include "tls/s2n_kem_core.h"

#include <stdint.h>

int s2n_ecdhe_server_key_recv(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_ecc_params *ecc_params = &conn->secure.server_ecc_params;

    /* Read server ECDH params and save the raw data for later hashing */
    GUARD(s2n_ecc_read_ecc_params(ecc_params, in, data_to_sign));
    return 0;
}


int s2n_ecdhe_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_ecc_params *ecc_params = &conn->secure.server_ecc_params;

    /* Generate an ephemeral key  */
    GUARD(s2n_ecc_generate_ephemeral_key(ecc_params));

    /* Write it out and calculate the hash */
    GUARD(s2n_ecc_write_ecc_params(ecc_params, out, data_to_sign));
    return 0;
}

int s2n_ecdhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_ecc_params *ecc_params = &conn->secure.server_ecc_params;

    GUARD(s2n_ecc_compute_shared_secret_as_client(ecc_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_ecc_params_free(ecc_params));

    return 0;
}

int s2n_ecdhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_ecc_params *ecc_params = &conn->secure.server_ecc_params;

    /* Get the shared key */
    GUARD(s2n_ecc_compute_shared_secret_as_server(ecc_params, in, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_ecc_params_free(ecc_params));

    return 0;
}
