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
#include "tls/s2n_async_pkey.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"
#include "error/s2n_errno.h"
#include "s2n.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

typedef enum { S2N_ASYNC_DECRYPT, S2N_ASYNC_SIGN } s2n_async_pkey_op_type;

struct s2n_async_pkey_decrypt_data {
    s2n_async_pkey_decrypt_complete on_complete;
    struct s2n_blob                 encrypted;
    struct s2n_blob                 decrypted;
    unsigned                        rsa_failed : 1;
};

struct s2n_async_pkey_sign_data {
    s2n_async_pkey_sign_complete on_complete;
    struct s2n_hash_state        digest;
    s2n_signature_algorithm      sig_alg;
    struct s2n_blob              signature;
};

struct s2n_async_pkey_op {
    s2n_async_pkey_op_type type;
    struct s2n_connection *conn;
    unsigned               complete : 1;
    unsigned               applied  : 1;
    union {
        struct s2n_async_pkey_decrypt_data decrypt;
        struct s2n_async_pkey_sign_data    sign;
    } op;
};

struct s2n_async_pkey_op_actions {
    int (*perform)(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey);
    int (*apply)(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
    int (*free)(struct s2n_async_pkey_op *op);
};

static int s2n_async_pkey_sign_async(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                                     struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete);
static int s2n_async_pkey_sign_sync(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                                    struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete);

static int s2n_async_pkey_decrypt_async(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                        struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete);
static int s2n_async_pkey_decrypt_sync(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                       struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete);

static int s2n_async_pkey_decrypt_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey);
static int s2n_async_pkey_decrypt_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
static int s2n_async_pkey_decrypt_free(struct s2n_async_pkey_op *op);

static int s2n_async_pkey_sign_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey);
static int s2n_async_pkey_sign_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
static int s2n_async_pkey_sign_free(struct s2n_async_pkey_op *op);

static const struct s2n_async_pkey_op_actions s2n_async_pkey_decrypt_op = { .perform = &s2n_async_pkey_decrypt_perform,
                                                                            .apply   = &s2n_async_pkey_decrypt_apply,
                                                                            .free    = &s2n_async_pkey_decrypt_free };

static const struct s2n_async_pkey_op_actions s2n_async_pkey_sign_op = { .perform = &s2n_async_pkey_sign_perform,
                                                                         .apply   = &s2n_async_pkey_sign_apply,
                                                                         .free    = &s2n_async_pkey_sign_free };

static const struct s2n_async_pkey_op_actions *s2n_async_get_actions(s2n_async_pkey_op_type type)
{
    switch (type) {
        case S2N_ASYNC_DECRYPT:
            return &s2n_async_pkey_decrypt_op;
        case S2N_ASYNC_SIGN:
            return &s2n_async_pkey_sign_op;
            /* No default for compiler warnings */
    }

    return NULL;
}

int s2n_async_pkey_decrypt(struct s2n_connection *conn, struct s2n_blob *encrypted, struct s2n_blob *init_decrypted,
                      s2n_async_pkey_decrypt_complete on_complete)
{
    notnull_check(conn);
    notnull_check(encrypted);
    notnull_check(on_complete);

    if (conn->config->async_pkey_cb) {
        GUARD(s2n_async_pkey_decrypt_async(conn, encrypted, init_decrypted, on_complete));
    } else {
        GUARD(s2n_async_pkey_decrypt_sync(conn, encrypted, init_decrypted, on_complete));
    }

    return 0;
}

int s2n_async_pkey_decrypt_async(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                 struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete)
{
    S2N_ERROR_IF(conn->handshake.async_state != S2N_ASYNC_NOT_INVOKED, S2N_ERR_ASYNC_MORE_THAN_ONE);

    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_async_pkey_op)));
    GUARD(s2n_blob_zero(&mem));
    struct s2n_async_pkey_op *op = ( void * )mem.data;

    op->type = S2N_ASYNC_DECRYPT;
    op->conn = conn;

    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;
    decrypt->on_complete                        = on_complete;

    GUARD(s2n_dup(encrypted, &decrypt->encrypted));
    GUARD(s2n_dup(init_decrypted, &decrypt->decrypted));

    /* Block the handshake and set async state to invoking to block async states */
    GUARD(s2n_conn_set_handshake_read_block(conn));
    conn->handshake.async_state = S2N_ASYNC_INVOKING;

    /* async_pkey will own the op, clean the mem blob to avoid freeing op */
    GUARD(s2n_blob_init(&mem, NULL, 0));

    S2N_ERROR_IF(conn->config->async_pkey_cb(conn, op) < 0, S2N_ERR_ASYNC_CALLBACK_FAILED);

    /* Set state to waiting to allow op to be consumed by connection */
    conn->handshake.async_state = S2N_ASYNC_INVOKED_WAITING;

    /* Return an async blocked error to drop out of s2n_negotiate loop */
    S2N_ERROR(S2N_ERR_ASYNC_BLOCKED);
}

int s2n_async_pkey_decrypt_sync(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete)
{
    const struct s2n_pkey *pkey = conn->handshake_params.our_chain_and_key->private_key;

    int rsa_failed = !!s2n_pkey_decrypt(pkey, encrypted, init_decrypted);
    GUARD(on_complete(conn, rsa_failed, init_decrypted));

    return 0;
}

int s2n_async_pkey_sign(struct s2n_connection *conn, s2n_signature_algorithm sig_alg, struct s2n_hash_state *digest,
                   s2n_async_pkey_sign_complete on_complete)
{
    notnull_check(conn);
    notnull_check(digest);
    notnull_check(on_complete);

    if (conn->config->async_pkey_cb) {
        GUARD(s2n_async_pkey_sign_async(conn, sig_alg, digest, on_complete));
    } else {
        GUARD(s2n_async_pkey_sign_sync(conn, sig_alg, digest, on_complete));
    }

    return 0;
}

int s2n_async_pkey_sign_async(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                              struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete)
{
    S2N_ERROR_IF(conn->handshake.async_state != S2N_ASYNC_NOT_INVOKED, S2N_ERR_ASYNC_MORE_THAN_ONE);

    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_async_pkey_op)));
    GUARD(s2n_blob_zero(&mem));
    struct s2n_async_pkey_op *op = ( void * )mem.data;

    op->type = S2N_ASYNC_SIGN;
    op->conn = conn;

    struct s2n_async_pkey_sign_data *sign = &op->op.sign;
    sign->on_complete                     = on_complete;
    sign->sig_alg                         = sig_alg;

    GUARD(s2n_hash_new(&sign->digest));
    GUARD(s2n_hash_copy(&sign->digest, digest));

    /* Block the handshake and set async state to invoking to block async states */
    GUARD(s2n_conn_set_handshake_read_block(conn));
    conn->handshake.async_state = S2N_ASYNC_INVOKING;

    /* async_pkey will own the op, clean the mem blob to avoid freeing op */
    GUARD(s2n_blob_init(&mem, NULL, 0));

    S2N_ERROR_IF(conn->config->async_pkey_cb(conn, op) < 0, S2N_ERR_ASYNC_CALLBACK_FAILED);

    /* Set state to waiting to allow op to be consumed by connection */
    conn->handshake.async_state = S2N_ASYNC_INVOKED_WAITING;

    /* Return an async blocked error to drop out of s2n_negotiate loop */
    S2N_ERROR(S2N_ERR_ASYNC_BLOCKED);
}

int s2n_async_pkey_sign_sync(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                             struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete)
{
    const struct s2n_pkey *pkey = conn->handshake_params.our_chain_and_key->private_key;
    DEFER_CLEANUP(struct s2n_blob signed_content = { 0 }, s2n_free);

    uint32_t maximum_signature_length = s2n_pkey_size(pkey);
    GUARD(s2n_alloc(&signed_content, maximum_signature_length));

    GUARD(s2n_pkey_sign(pkey, sig_alg, digest, &signed_content));

    GUARD(on_complete(conn, &signed_content));

    return 0;
}

int s2n_async_pkey_op_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *key)
{
    notnull_check(op);
    S2N_ERROR_IF(op->complete, S2N_ERR_ASYNC_ALREADY_PERFORMED);

    const struct s2n_async_pkey_op_actions *actions = s2n_async_get_actions(op->type);
    notnull_check(actions);

    GUARD(actions->perform(op, key));

    op->complete = 1;

    return 0;
}

int s2n_async_pkey_op_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn)
{
    notnull_check(op);
    S2N_ERROR_IF(!op->complete, S2N_ERR_ASYNC_NOT_PERFORMED);
    S2N_ERROR_IF(op->applied, S2N_ERR_ASYNC_ALREADY_APPLIED);
    /* We could have just used op->conn and removed a conn argument, but we want caller
     * to be explicit about connection it wants to resume. Plus this gives more
     * protections in cases if caller frees connection object and then tries to resume
     * the connection. */
    S2N_ERROR_IF(op->conn != conn, S2N_ERR_ASYNC_WRONG_CONNECTION);
    S2N_ERROR_IF(conn->handshake.async_state == S2N_ASYNC_INVOKING, S2N_ERR_ASYNC_APPLY_WHILE_INVOKING);
    S2N_ERROR_IF(conn->handshake.async_state != S2N_ASYNC_INVOKED_WAITING, S2N_ERR_ASYNC_WRONG_CONNECTION);

    const struct s2n_async_pkey_op_actions *actions = s2n_async_get_actions(op->type);
    notnull_check(actions);

    GUARD(actions->apply(op, conn));

    op->applied = 1;
    conn->handshake.async_state = S2N_ASYNC_INVOKED_COMPLETE;

    /* Free up the decrypt/sign structs to avoid storing secrets for too long */
    GUARD(actions->free(op));

    return 0;
}

int s2n_async_pkey_op_free(struct s2n_async_pkey_op *op)
{
    const struct s2n_async_pkey_op_actions *actions = s2n_async_get_actions(op->type);
    notnull_check(actions);

    /* If applied the decrypt/sign structs were released in apply call */
    if (!op->applied) {
        GUARD(actions->free(op));
    }

    GUARD(s2n_free_object(( uint8_t ** )&op, sizeof(struct s2n_async_pkey_op)));

    return 0;
}

int s2n_async_pkey_decrypt_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey)
{
    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;

    decrypt->rsa_failed = !!s2n_pkey_decrypt(pkey, &decrypt->encrypted, &decrypt->decrypted);

    return 0;
}

int s2n_async_pkey_decrypt_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn)
{
    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;

    GUARD(decrypt->on_complete(conn, decrypt->rsa_failed, &decrypt->decrypted));

    return 0;
}

int s2n_async_pkey_decrypt_free(struct s2n_async_pkey_op *op)
{
    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;

    GUARD(s2n_blob_zero(&decrypt->decrypted));
    GUARD(s2n_blob_zero(&decrypt->encrypted));
    GUARD(s2n_free(&decrypt->decrypted));
    GUARD(s2n_free(&decrypt->encrypted));

    return 0;
}

int s2n_async_pkey_sign_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey)
{
    struct s2n_async_pkey_sign_data *sign = &op->op.sign;

    uint32_t maximum_signature_length = s2n_pkey_size(pkey);
    GUARD(s2n_alloc(&sign->signature, maximum_signature_length));

    GUARD(s2n_pkey_sign(pkey, sign->sig_alg, &sign->digest, &sign->signature));

    return 0;
}

int s2n_async_pkey_sign_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn)
{
    struct s2n_async_pkey_sign_data *sign = &op->op.sign;

    GUARD(sign->on_complete(conn, &sign->signature));

    return 0;
}

int s2n_async_pkey_sign_free(struct s2n_async_pkey_op *op)
{
    struct s2n_async_pkey_sign_data *sign = &op->op.sign;

    GUARD(s2n_hash_free(&sign->digest));
    GUARD(s2n_free(&sign->signature));

    return 0;
}

