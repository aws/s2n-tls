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
#include "assert.h"
#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_resume.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"


static int s2n_gen_master_secret(struct s2n_connection *conn)
{
    struct s2n_blob pms;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    assert(S2N_TLS_PROTOCOL_VERSION_LEN > 1);
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    pms.data = conn->secure.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    /* Set rsa_failed to 1, if it isn't already, if the protocol version isn't what we expect */
    conn->handshake.rsa_failed |= !s2n_constant_time_equals(client_protocol_version, pms.data, S2N_TLS_PROTOCOL_VERSION_LEN);

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &pms));
    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&pms));
    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));
    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }
    return 0;
}

/*!
 *
 * @param connection meta data
 * @return Return '0' if succeeded, '-1' if error occurred and '1' if waiting on the application.
 */
static int s2n_rsa_client_key_recv_with_external_decrypt(struct s2n_connection *conn)
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
      encrypted.size));

    return 0;
}

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

    S2N_ERROR_IF(length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Keep a copy of the client protocol version in wire format */
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* Decrypt the pre-master secret */
    struct s2n_blob pms, encrypted;
    pms.data = conn->secure.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    encrypted.size = s2n_stuffer_data_available(in);
    encrypted.data = s2n_stuffer_raw_read(in, length);
    notnull_check(encrypted.data);
    gt_check(encrypted.size, 0);

    /* First: use a random pre-master secret */
    GUARD(s2n_get_private_random_data(&pms));
    conn->secure.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->secure.rsa_premaster_secret[1] = client_protocol_version[1];

    /* Set rsa_failed to 1 if s2n_pkey_decrypt returns anything other than zero */
    conn->handshake.rsa_failed = !!s2n_pkey_decrypt(&conn->config->cert_and_key_pairs->private_key, &encrypted, &pms);

    return s2n_gen_master_secret(conn);
}

static int s2n_dhe_client_key_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob shared_key = {0};

    /* Get the shared key */
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_compute_shared_secret_as_server(&conn->secure.server_ecc_params, in, &shared_key));
    } else {
        GUARD(s2n_dh_compute_shared_secret_as_server(&conn->secure.server_dh_params, in, &shared_key));
    }

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &shared_key));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key));
    GUARD(s2n_free(&shared_key));

    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));

    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }

    /* We don't need the server params any more */
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));
    } else {
        GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    }

    return 0;
}

static int s2n_free_external_ctx_pre_master_key(struct s2n_connection *conn)
{
    notnull_check(conn);
    struct s2n_blob mem = {0};
    GUARD(s2n_blob_init(&mem, conn->external_ctx.pre_master_key, conn->external_ctx.pre_master_key_size));
    GUARD(s2n_free(&mem));
    conn->external_ctx.pre_master_key = NULL;
    conn->external_ctx.pre_master_key_size = 0;

    return 0;
}

static int s2n_rsa_client_key_external(struct s2n_connection *conn)
{
    notnull_check(conn);
    notnull_check(conn->config);
    notnull_check(conn->config->external_rsa_decrypt);
    notnull_check(conn->external_ctx.pre_master_key);

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
            memcpy_check(conn->secure.rsa_premaster_secret, conn->external_ctx.pre_master_key, conn->external_ctx.pre_master_key_size);

            /* free the memory of the context */
            GUARD(s2n_free_external_ctx_pre_master_key(conn));

            return s2n_gen_master_secret(conn);
        }
            /* external rsa decrypt has completed the request but error occurred */
        case S2N_EXTERNAL_ERROR: {
            conn->handshake.rsa_failed = 1;

            /* free the memory of the context */
            GUARD(s2n_free_external_ctx_pre_master_key(conn));

            S2N_ERROR(S2N_ERR_EXTERNAL_FAILURE);
        }
        default:
            /* the status is not anything we expected. Something went wrong and need ot set rsa_failed to 1. */
            conn->handshake.rsa_failed = 1;

            /* free the memory of the context */
            GUARD(s2n_free_external_ctx_pre_master_key(conn));

            S2N_ERROR(S2N_ERR_EXTERNAL_CTX_STATUS_INVALID);
    }
}

int s2n_client_key_recv(struct s2n_connection *conn)
{
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_DH) {
        return s2n_dhe_client_key_recv(conn);
    } else {
        if (conn->config->external_rsa_decrypt) {
            /* use external rsa decrypt*/
            return s2n_rsa_client_key_recv_with_external_decrypt(conn);
        } else {
            return s2n_rsa_client_key_recv(conn);
        }
    }
}

int s2n_client_key_external(struct s2n_connection *conn)
{
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_DH) {
        /* Nothing to do for DHE at this time. */
        return 0;
    } else {
        if (conn->config->external_rsa_decrypt) {
            /* use external rsa decrypt*/
            return s2n_rsa_client_key_external(conn);
        }

        return 0;
    }
}

static int s2n_dhe_client_key_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_blob shared_key = {0};

    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_compute_shared_secret_as_client(&conn->secure.server_ecc_params, out, &shared_key));
    } else {
        GUARD(s2n_dh_compute_shared_secret_as_client(&conn->secure.server_dh_params, out, &shared_key));
    }

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &shared_key));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key));
    GUARD(s2n_free(&shared_key));

    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));

    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }

    /* We don't need the server params any more */
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));
    } else {
        GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    }

    return 0;
}

static int s2n_rsa_client_key_send(struct s2n_connection *conn)
{
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    struct s2n_blob pms = {0};
    pms.data = conn->secure.rsa_premaster_secret;
    pms.size = S2N_TLS_SECRET_LEN;

    GUARD(s2n_get_private_random_data(&pms));

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
    GUARD(s2n_pkey_encrypt(&conn->secure.server_public_key, &pms, &encrypted));

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));

    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, &pms));

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&pms));

    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));

    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }

    return 0;
}

int s2n_client_key_send(struct s2n_connection *conn)
{
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_DH) {
        return s2n_dhe_client_key_send(conn);
    } else {
        return s2n_rsa_client_key_send(conn);
    }
}
