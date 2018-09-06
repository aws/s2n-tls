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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_kem_core.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_tls_digest_preferences.h"

#include "utils/s2n_safety.h"
#include "s2n_kem_core.h"

#include <stdint.h>

int s2n_dhe_server_key_recv(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_dh_params *dhe_params = &conn->secure.server_dh_params;

    struct s2n_blob p, g, Ys;
    uint16_t p_length;
    uint16_t g_length;
    uint16_t Ys_length;

    /* Keep a copy to the start of the whole structure for the signature check */
    data_to_sign->data = s2n_stuffer_raw_read(in, 0);
    notnull_check(data_to_sign->data);

    /* Read each of the three elements in */
    GUARD(s2n_stuffer_read_uint16(in, &p_length));
    p.size = p_length;
    p.data = s2n_stuffer_raw_read(in, p.size);
    notnull_check(p.data);

    GUARD(s2n_stuffer_read_uint16(in, &g_length));
    g.size = g_length;
    g.data = s2n_stuffer_raw_read(in, g.size);
    notnull_check(g.data);

    GUARD(s2n_stuffer_read_uint16(in, &Ys_length));
    Ys.size = Ys_length;
    Ys.data = s2n_stuffer_raw_read(in, Ys.size);
    notnull_check(Ys.data);

    /* Now we know the total size of the structure */
    data_to_sign->size = 2 + p_length + 2 + g_length + 2 + Ys_length;

    /* Copy the DH details */
    GUARD(s2n_dh_p_g_Ys_to_dh_params(dhe_params, &p, &g, &Ys));

    return 0;
}

int s2n_dhe_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_dh_params *dhe_params = &conn->secure.server_dh_params;

    /* Generate an ephemeral key */
    GUARD(s2n_dh_generate_ephemeral_key(dhe_params));

    /* Write it out */
    GUARD(s2n_dh_params_to_p_g_Ys(dhe_params, out, data_to_sign));

    return 0;
}

int s2n_dhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_dh_params *dhe_params = &conn->secure.server_dh_params;

    GUARD(s2n_dh_compute_shared_secret_as_client(dhe_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(dhe_params));

    return 0;
}

int s2n_dhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_dh_params *dhe_params = &conn->secure.server_dh_params;

    /* Get the shared key */
    GUARD(s2n_dh_compute_shared_secret_as_server(dhe_params, in, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(dhe_params));

    return 0;
}
