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

#include <s2n.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

static int s2n_rsa_client_key_recv(struct s2n_connection *conn, const char **err)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint16_t length;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = s2n_stuffer_data_available(in);
    } else {
        GUARD(s2n_stuffer_read_uint16(in, &length, err));
    }

    if (length > s2n_stuffer_data_available(in)) {
        *err = "TLS premaster secret length is an invalid size";
        return -1;
    }

    /* Decrypt the pre-master secret */
    struct s2n_blob pms, encrypted;
    pms.data = conn->pending.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    encrypted.size = s2n_stuffer_data_available(in);
    encrypted.data = s2n_stuffer_raw_read(in, length, err);

    if (s2n_rsa_decrypt(&conn->config->cert_and_key_pairs->private_key, &encrypted, &pms, err) < 0) {
        conn->handshake.rsa_failed = 1;
    }

    /* Check the client version number against the actual version number */
    if (pms.data[0] * 10 + pms.data[1] != conn->client_protocol_version) {
        conn->handshake.rsa_failed = 1;
    }

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &pms, err));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&pms, err));

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

static int s2n_dhe_client_key_recv(struct s2n_connection *conn, const char **err)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob Yc;
    struct s2n_blob shared_key;
    uint16_t length;

    GUARD(s2n_stuffer_read_uint16(in, &length, err));

    Yc.size = length;
    Yc.data = s2n_stuffer_raw_read(in, Yc.size, err);
    notnull_check(Yc.data);

    /* Get the shared key */
    GUARD(s2n_dh_compute_shared_secret_as_server(&conn->pending.server_dh_params, &Yc, &shared_key, err));

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &shared_key, err));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key, err));
    GUARD(s2n_free(&shared_key, err));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->pending.server_dh_params, err));

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

int s2n_client_key_recv(struct s2n_connection *conn, const char **err)
{
    if (conn->pending.cipher_suite->key_exchange_alg == S2N_RSA) {
        return s2n_rsa_client_key_recv(conn, err);
    } else if (conn->pending.cipher_suite->key_exchange_alg == S2N_DHE) {
        return s2n_dhe_client_key_recv(conn, err);
    }

    *err = "Unrecognised key exchange algorithm";
    return -1;
}

static int s2n_dhe_client_key_send(struct s2n_connection *conn, const char **err)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_blob shared_key;

    GUARD(s2n_dh_compute_shared_secret_as_client(&conn->pending.server_dh_params, out, &shared_key, err));

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &shared_key, err));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key, err));
    GUARD(s2n_free(&shared_key, err));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->pending.server_dh_params, err));

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

static int s2n_rsa_client_key_send(struct s2n_connection *conn, const char **err)
{
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    memcpy_check(conn->pending.rsa_premaster_secret, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN);
    GUARD(s2n_get_random_data(conn->pending.rsa_premaster_secret + S2N_TLS_PROTOCOL_VERSION_LEN, S2N_TLS_SECRET_LEN - S2N_TLS_PROTOCOL_VERSION_LEN, err));

    struct s2n_blob pms;
    pms.data = conn->pending.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    int encrypted_size = s2n_rsa_public_encrypted_size(&conn->pending.server_rsa_public_key, err);
    if (encrypted_size < 0 || encrypted_size > 0xffff) {
        *err = "Error predicting encrypted size";
        return -1;
    }

    if (conn->actual_protocol_version > S2N_SSLv3) {
        GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, encrypted_size, err));
    }

    struct s2n_blob encrypted;
    encrypted.data = s2n_stuffer_raw_write(&conn->handshake.io, encrypted_size, err);
    encrypted.size = encrypted_size;
    notnull_check(encrypted.data);

    /* Encrypt the secret and send it on */
    GUARD(s2n_rsa_encrypt(&conn->pending.server_rsa_public_key, &pms, &encrypted, err));

    /* We don't need the key any more, so free it */
    GUARD(s2n_rsa_public_key_free(&conn->pending.server_rsa_public_key, err));

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &pms, err));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&pms, err));

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

int s2n_client_key_send(struct s2n_connection *conn, const char **err)
{
    if (conn->pending.cipher_suite->key_exchange_alg == S2N_RSA) {
        return s2n_rsa_client_key_send(conn, err);
    } else if (conn->pending.cipher_suite->key_exchange_alg == S2N_DHE) {
        return s2n_dhe_client_key_send(conn, err);
    }

    *err = "Unrecognised key exchange algorithm";
    return -1;
}
