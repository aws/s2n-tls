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

#include "tls/s2n_kem.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_resume.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

static int calculate_keys(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_tls_prf_master_secret(conn, shared_key));
    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(shared_key));
    if (shared_key->allocated) {
        GUARD(s2n_free(shared_key));
    }
    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));
    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }
    return 0;
}

int s2n_free_external_ctx_pre_master_key(struct s2n_connection *conn)
{
    notnull_check(conn);
    s2n_free_object(&(conn->external_ctx.pre_master_key), conn->external_ctx.pre_master_key_size);
    conn->external_ctx.pre_master_key_size = 0;

    return 0;
}

int s2n_rsa_client_key_external(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    notnull_check(conn);
    notnull_check(conn->config);
    notnull_check(conn->config->external_rsa_decrypt);

    /* Keep a copy of the client protocol version in wire format */
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* get the status of the external decryption of this connection */
    switch (conn->external_ctx.pre_master_key_status) {
        /* external rsa decrypt has already been invoked and we are just waiting for the result. Return '1' to indicate that */
        case S2N_EXTERNAL_INVOKED: {
            return 1;
        }
        /* external rsa decrypt has returned the result. Let's proceed to generate the master secret */
        case S2N_EXTERNAL_RETURNED: {
            /* verify the size of the array */
            eq_check(S2N_TLS_SECRET_LEN, conn->external_ctx.pre_master_key_size);

            /* verify the client protocol version */
            /* The pre-master key is of 48 bytes and is generated at the client side by concatenating the 2 bytes protocol
             * version and 46 bytes of random data. The whole 48 bytes are encrypted by the server's RSA public key. */
            eq_check(client_protocol_version[0], conn->external_ctx.pre_master_key[0]);
            eq_check(client_protocol_version[1], conn->external_ctx.pre_master_key[1]);

            /* copy the result back */
            memcpy_check(conn->secure.rsa_premaster_secret, conn->external_ctx.pre_master_key, S2N_TLS_SECRET_LEN);

            shared_key->data = conn->secure.rsa_premaster_secret;
            shared_key->size = S2N_TLS_SECRET_LEN;

            /* ready to calculate the shared key now, will move forward to the next state */
            GUARD(calculate_keys(conn, shared_key));

            /* free the memory of the context */
            GUARD(s2n_free_external_ctx_pre_master_key(conn));
            return 0;
        }
        /* external rsa decrypt has completed the request but error occurred */
        case S2N_EXTERNAL_ERROR: {
            conn->handshake.rsa_failed = 1;

            /* free the memory of the context */
            GUARD(s2n_free_external_ctx_pre_master_key(conn));

            S2N_ERROR(S2N_ERR_EXTERNAL_FAILURE);
        }
        default: {
            /* the status is not anything we expected. Something went wrong and need ot set rsa_failed to 1. */
            conn->handshake.rsa_failed = 1;

            /* free the memory of the context */
            GUARD(s2n_free_external_ctx_pre_master_key(conn));

            S2N_ERROR(S2N_ERR_EXTERNAL_CTX_STATUS_INVALID);
        }
    }

    return -1;
}

int s2n_ecdhe_client_key_external(struct s2n_connection* conn, struct s2n_blob* shared_key)
{
    /* Nothing to do for ECDHE at this state. */
    return 0;
}

int s2n_dhe_client_key_external(struct s2n_connection* conn, struct s2n_blob* shared_key)
{
    /* Nothing to do for DHE at this state. */
    return 0;
}

int s2n_client_key_external(struct s2n_connection *conn)
{
    if (NULL == conn->config->external_rsa_decrypt) {
        /* we are not using external rsa decrypt, nothing to do here */
        return 0;
    }

    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_external(key_exchange, conn, &shared_key));

    return 0;
}

/*!
 * @param connection meta data
 * @return Return '0' if succeeded, '-1' if error occurred and '1' if waiting on the application.
 */
int s2n_rsa_client_key_recv_with_external_decrypt(struct s2n_connection *conn)
{
    notnull_check(conn);
    notnull_check(conn->config);
    notnull_check(conn->config->external_rsa_decrypt);
    eq_check(S2N_EXTERNAL_NOT_INVOKED, conn->external_ctx.pre_master_key_status);
    eq_check(NULL, conn->external_ctx.pre_master_key);
    eq_check(0, conn->external_ctx.pre_master_key_size);

    /* Keep a copy of the client protocol version in wire format */
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* If the external rsa context is null, it means the external rsa decrypt has not been invoked yet. We will then:
     *  - instantiate the external rsa context,
     *  - invoke the external rsa decrypt
     *  - set the status flag in the external rsa context to S2N_EXTERNAL_INVOKED which indicates we are waiting for the external decrypt to return. */

    /* Allocate memory for the external context */
    struct s2n_blob mem = {0};
    GUARD(s2n_alloc(&mem, S2N_TLS_SECRET_LEN));
    conn->external_ctx.pre_master_key = mem.data;
    conn->external_ctx.pre_master_key_size = mem.size;
    S2N_ERROR_IF(NULL == conn->external_ctx.pre_master_key, S2N_ERR_ALLOC);

    /* set the status to in progress */
    conn->external_ctx.pre_master_key_status = S2N_EXTERNAL_INVOKED;

    /* set the size of the payload */

    /* set the client protocol version */
    conn->external_ctx.pre_master_key[0] = client_protocol_version[0];
    conn->external_ctx.pre_master_key[1] = client_protocol_version[1];

    struct s2n_stuffer *in = &conn->handshake.io;

    uint16_t length;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = s2n_stuffer_data_available(in);
    } else {
        GUARD(s2n_stuffer_read_uint16(in, &length));
    }

    S2N_ERROR_IF(length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Decrypt the pre-master secret */
    struct s2n_blob encrypted;
    encrypted.size = s2n_stuffer_data_available(in);
    encrypted.data = s2n_stuffer_raw_read(in, length);
    notnull_check(encrypted.data);
    gt_check(encrypted.size, 0);

    /* Initialize use a random pre-master secret */
    struct s2n_blob pms;
    pms.data = conn->secure.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;
    GUARD(s2n_get_private_random_data(&pms));
    conn->secure.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->secure.rsa_premaster_secret[1] = client_protocol_version[1];

    /* Invoke the external decrypt */
    GUARD(conn->config->external_rsa_decrypt((int32_t*)(&conn->external_ctx.pre_master_key_status),
                                             conn->external_ctx.pre_master_key_size,
                                             conn->external_ctx.pre_master_key,
                                             encrypted.data,
                                             encrypted.size,
                                             conn->context));

    return 0;
}

int s2n_rsa_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    /* check if external TLS key server is expected to be used */
    if (conn->config->external_rsa_decrypt) {
        s2n_rsa_client_key_recv_with_external_decrypt(conn);
        /* shared key will be calculated in the next state, not need at this time. */
        return 0;
    }

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
    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    struct s2n_blob encrypted = {.size = length, .data = s2n_stuffer_raw_read(in, length)};
    notnull_check(encrypted.data);
    gt_check(encrypted.size, 0);

    /* First: use a random pre-master secret */
    GUARD(s2n_get_private_random_data(shared_key));
    conn->secure.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->secure.rsa_premaster_secret[1] = client_protocol_version[1];

    /* Set rsa_failed to 1 if s2n_pkey_decrypt returns anything other than zero */
    conn->handshake.rsa_failed = !!s2n_pkey_decrypt(conn->handshake_params.our_chain_and_key->private_key, &encrypted, shared_key);

    /* Set rsa_failed to 1, if it isn't already, if the protocol version isn't what we expect */
    conn->handshake.rsa_failed |= !s2n_constant_time_equals(client_protocol_version, shared_key->data, S2N_TLS_PROTOCOL_VERSION_LEN);

    GUARD(calculate_keys(conn, shared_key));
    return 0;
}

int s2n_dhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get the shared key */
    GUARD(s2n_dh_compute_shared_secret_as_server(&conn->secure.server_dh_params, in, shared_key));
    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));

    GUARD(calculate_keys(conn, shared_key));
    return 0;
}

int s2n_ecdhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get the shared key */
    GUARD(s2n_ecc_compute_shared_secret_as_server(&conn->secure.server_ecc_params, in, shared_key));
    /* We don't need the server params any more */
    GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));

    GUARD(calculate_keys(conn, shared_key));
    return 0;
}

int s2n_kem_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    kem_ciphertext_key_size ciphertext_length;

    GUARD(s2n_stuffer_read_uint16(in, &ciphertext_length));
    S2N_ERROR_IF(ciphertext_length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    const struct s2n_blob ciphertext = {.size = ciphertext_length, .data = s2n_stuffer_raw_read(in, ciphertext_length)};
    notnull_check(ciphertext.data);

    GUARD(s2n_kem_decapsulate(&conn->secure.s2n_kem_keys, shared_key, &ciphertext));

    GUARD(s2n_kem_free(&conn->secure.s2n_kem_keys));
    return 0;
}

int s2n_client_key_recv(struct s2n_connection *conn)
{
    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_recv(key_exchange, conn, &shared_key));

    return 0;
}

int s2n_dhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    GUARD(s2n_dh_compute_shared_secret_as_client(&conn->secure.server_dh_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    return 0;
}

int s2n_ecdhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    GUARD(s2n_ecc_compute_shared_secret_as_client(&conn->secure.server_ecc_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));
    return 0;
}

int s2n_rsa_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
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
        GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, encrypted_size));
    }

    struct s2n_blob encrypted = {0};
    encrypted.data = s2n_stuffer_raw_write(&conn->handshake.io, encrypted_size);
    encrypted.size = encrypted_size;
    notnull_check(encrypted.data);

    /* Encrypt the secret and send it on */
    GUARD(s2n_pkey_encrypt(&conn->secure.server_public_key, shared_key, &encrypted));

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));
    return 0;
}

int s2n_kem_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    const struct s2n_kem *kem = conn->secure.s2n_kem_keys.negotiated_kem;

    GUARD(s2n_stuffer_write_uint16(out, kem->ciphertext_length));

    /* The ciphertext is not needed after this method, write it straight to the stuffer */
    struct s2n_blob ciphertext = {.data = s2n_stuffer_raw_write(out, kem->ciphertext_length), .size = kem->ciphertext_length};
    notnull_check(ciphertext.data);

    GUARD(s2n_kem_encapsulate(&conn->secure.s2n_kem_keys, shared_key, &ciphertext));
    GUARD(s2n_kem_free(&conn->secure.s2n_kem_keys));
    return 0;
}

int s2n_client_key_send(struct s2n_connection *conn)
{
    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_send(key_exchange, conn, &shared_key));

    GUARD(calculate_keys(conn, &shared_key));
    return 0;
}
