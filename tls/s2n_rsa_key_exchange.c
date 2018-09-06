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

#include "tls/s2n_kem_core.h"
#include "tls/s2n_resume.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "s2n_kem_core.h"
#include "s2n_connection.h"

#include <stdint.h>

// The server should never receive an RSA key during the key exchange
int s2n_rsa_server_key_recv(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    S2N_ERROR(S2N_ERR_HANDSHAKE_STATE);
}

// The server should never send an additional RSA key during the key exchange
int s2n_rsa_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    S2N_ERROR(S2N_ERR_HANDSHAKE_STATE);
}

int s2n_rsa_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    uint16_t length;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = s2n_stuffer_data_available(in);
    } else {
        GUARD(s2n_stuffer_read_uint16(in, &length));
    }

    S2N_ERROR_IF(length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Keep a copy of the client protocol version in wire format */
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* Decrypt the pre-master secret */
    struct s2n_blob encrypted;
    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    encrypted.size = s2n_stuffer_data_available(in);
    encrypted.data = s2n_stuffer_raw_read(in, length);
    notnull_check(encrypted.data);
    gt_check(encrypted.size, 0);

    /* First: use a random pre-master secret */
    GUARD(s2n_get_private_random_data(shared_key));
    conn->secure.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->secure.rsa_premaster_secret[1] = client_protocol_version[1];

    /* Set rsa_failed to 1 if s2n_pkey_decrypt returns anything other than zero */
    conn->handshake.rsa_failed = !!s2n_pkey_decrypt(&conn->config->cert_and_key_pairs->private_key, &encrypted, shared_key);

    /* Set rsa_failed to 1, if it isn't already, if the protocol version isn't what we expect */
    conn->handshake.rsa_failed |= !s2n_constant_time_equals(client_protocol_version, shared_key->data, S2N_TLS_PROTOCOL_VERSION_LEN);

    return 0;
}

int s2n_rsa_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    GUARD(s2n_get_private_random_data(shared_key));

    /* Over-write the first two bytes with the client protocol version, per RFC2246 7.4.7.1 */
    memcpy_check(conn->secure.rsa_premaster_secret, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN);

    int encrypted_size = s2n_pkey_size(&conn->secure.server_public_key);
    S2N_ERROR_IF(encrypted_size < 0 || encrypted_size > 0xffff, S2N_ERR_SIZE_MISMATCH);

    if (conn->actual_protocol_version > S2N_SSLv3) {
        GUARD(s2n_stuffer_write_uint16(out, encrypted_size));
    }

    struct s2n_blob encrypted = {0};
    encrypted.data = s2n_stuffer_raw_write(out, encrypted_size);
    encrypted.size = encrypted_size;
    notnull_check(encrypted.data);

    /* Encrypt the secret and send it on */
    GUARD(s2n_pkey_encrypt(&conn->secure.server_public_key, shared_key, &encrypted));

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));
    return 0;
}

