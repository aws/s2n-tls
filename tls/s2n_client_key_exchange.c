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

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

static int s2n_rsa_client_key_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    uint16_t length;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = s2n_stuffer_data_available(in);
    } else {
        GUARD(s2n_stuffer_read_uint16(in, &length));
    }

    if (length > s2n_stuffer_data_available(in)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    /* Keep a copy of the client protocol version in wire format */
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* Decrypt the pre-master secret */
    struct s2n_blob pms, encrypted;
    pms.data = conn->pending.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    encrypted.size = s2n_stuffer_data_available(in);
    encrypted.data = s2n_stuffer_raw_read(in, length);

    gt_check(encrypted.size, 0);

    /* First: use a random pre-master secret */
    GUARD(s2n_get_private_random_data(&pms));
    conn->pending.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->pending.rsa_premaster_secret[1] = client_protocol_version[1];


    /* Set rsa_failed to 1 if s2n_rsa_decrypt returns anything other than zero */
    conn->handshake.rsa_failed = !!s2n_rsa_decrypt(&conn->config->cert_and_key_pairs->private_key, &encrypted, &pms);

    /* Set rsa_failed to 1, if it isn't already, if the protocol version isn't what we expect */
    conn->handshake.rsa_failed |= !s2n_constant_time_equals(client_protocol_version, pms.data, S2N_TLS_PROTOCOL_VERSION_LEN);

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &pms));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&pms));

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

static int s2n_dhe_client_key_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob shared_key;

    /* Get the shared key */
    if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_compute_shared_secret_as_server(&conn->pending.server_ecc_params, in, &shared_key));
    } else {
        GUARD(s2n_dh_compute_shared_secret_as_server(&conn->pending.server_dh_params, in, &shared_key));
    }

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &shared_key));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key));
    GUARD(s2n_free(&shared_key));

    /* We don't need the server params any more */
    if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_params_free(&conn->pending.server_ecc_params));
    } else {
        GUARD(s2n_dh_params_free(&conn->pending.server_dh_params));
    }

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

int s2n_client_key_recv(struct s2n_connection *conn)
{
    if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_DH) {
        return s2n_dhe_client_key_recv(conn);
    } else {
        return s2n_rsa_client_key_recv(conn);
    }

    S2N_ERROR(S2N_ERR_INVALID_KEY_EXCHANGE_ALGORITHM);
}

static int s2n_dhe_client_key_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_blob shared_key;

    if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_compute_shared_secret_as_client(&conn->pending.server_ecc_params, out, &shared_key));
    } else {
        GUARD(s2n_dh_compute_shared_secret_as_client(&conn->pending.server_dh_params, out, &shared_key));
    }

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &shared_key));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key));
    GUARD(s2n_free(&shared_key));

    /* We don't need the server params any more */
    if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_params_free(&conn->pending.server_ecc_params));
    } else {
        GUARD(s2n_dh_params_free(&conn->pending.server_dh_params));
    }

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

static int s2n_rsa_client_key_send(struct s2n_connection *conn)
{
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;


    struct s2n_blob pms;
    pms.data = conn->pending.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    GUARD(s2n_get_private_random_data(&pms));

    /* Over-write the first two bytes with the client protocol version, per RFC2246 7.4.7.1 */
    memcpy_check(conn->pending.rsa_premaster_secret, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN);

    int encrypted_size = s2n_rsa_public_encrypted_size(&conn->pending.server_rsa_public_key);
    if (encrypted_size < 0 || encrypted_size > 0xffff) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }

    if (conn->actual_protocol_version > S2N_SSLv3) {
        GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, encrypted_size));
    }

    struct s2n_blob encrypted;
    encrypted.data = s2n_stuffer_raw_write(&conn->handshake.io, encrypted_size);
    encrypted.size = encrypted_size;
    notnull_check(encrypted.data);

    /* Encrypt the secret and send it on */
    GUARD(s2n_rsa_encrypt(&conn->pending.server_rsa_public_key, &pms, &encrypted));

    /* We don't need the key any more, so free it */
    GUARD(s2n_rsa_public_key_free(&conn->pending.server_rsa_public_key));

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &pms));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&pms));

    conn->handshake.next_state = CLIENT_CHANGE_CIPHER_SPEC;

    return 0;
}

int s2n_client_key_send(struct s2n_connection *conn)
{
    if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_DH) {
        return s2n_dhe_client_key_send(conn);
    } else {
        return s2n_rsa_client_key_send(conn);
    }

    S2N_ERROR(S2N_ERR_INVALID_KEY_EXCHANGE_ALGORITHM);
}
