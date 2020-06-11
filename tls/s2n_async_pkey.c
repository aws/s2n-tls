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
#include "utils/s2n_result.h"
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
    unsigned               applied : 1;
    union {
        struct s2n_async_pkey_decrypt_data decrypt;
        struct s2n_async_pkey_sign_data    sign;
    } op;
};

struct s2n_async_pkey_op_actions {
    S2N_RESULT (*perform)(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey);
    S2N_RESULT (*apply)(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
    S2N_RESULT (*free)(struct s2n_async_pkey_op *op);
};

static S2N_RESULT s2n_async_get_actions(s2n_async_pkey_op_type type, const struct s2n_async_pkey_op_actions **actions);

static S2N_RESULT s2n_async_pkey_op_allocate(struct s2n_async_pkey_op **op);

static S2N_RESULT s2n_async_pkey_sign_async(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                                            struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete);
static S2N_RESULT s2n_async_pkey_sign_sync(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                                           struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete);

static S2N_RESULT s2n_async_pkey_decrypt_async(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                               struct s2n_blob *               init_decrypted,
                                               s2n_async_pkey_decrypt_complete on_complete);
static S2N_RESULT s2n_async_pkey_decrypt_sync(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                              struct s2n_blob *               init_decrypted,
                                              s2n_async_pkey_decrypt_complete on_complete);

static S2N_RESULT s2n_async_pkey_decrypt_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey);
static S2N_RESULT s2n_async_pkey_decrypt_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
static S2N_RESULT s2n_async_pkey_decrypt_free(struct s2n_async_pkey_op *op);

static S2N_RESULT s2n_async_pkey_sign_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey);
static S2N_RESULT s2n_async_pkey_sign_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
static S2N_RESULT s2n_async_pkey_sign_free(struct s2n_async_pkey_op *op);

static const struct s2n_async_pkey_op_actions s2n_async_pkey_decrypt_op = { .perform = &s2n_async_pkey_decrypt_perform,
                                                                            .apply   = &s2n_async_pkey_decrypt_apply,
                                                                            .free    = &s2n_async_pkey_decrypt_free };

static const struct s2n_async_pkey_op_actions s2n_async_pkey_sign_op = { .perform = &s2n_async_pkey_sign_perform,
                                                                         .apply   = &s2n_async_pkey_sign_apply,
                                                                         .free    = &s2n_async_pkey_sign_free };

DEFINE_POINTER_CLEANUP_FUNC(struct s2n_async_pkey_op *, s2n_async_pkey_op_free);

static S2N_RESULT s2n_async_get_actions(s2n_async_pkey_op_type type, const struct s2n_async_pkey_op_actions **actions)
{
    ENSURE_REF(actions);

    switch (type) {
        case S2N_ASYNC_DECRYPT:
            *actions = &s2n_async_pkey_decrypt_op;
            return S2N_RESULT_OK;
        case S2N_ASYNC_SIGN:
            *actions = &s2n_async_pkey_sign_op;
            return S2N_RESULT_OK;
            /* No default for compiler warnings */
    }

    return S2N_RESULT_ERROR;
}

static S2N_RESULT s2n_async_pkey_op_allocate(struct s2n_async_pkey_op **op)
{
    ENSURE_REF(op);
    ENSURE(*op == NULL, S2N_ERR_SAFETY);

    /* allocate memory */
    DEFER_CLEANUP(struct s2n_blob mem = {0}, s2n_free);
    GUARD_AS_RESULT(s2n_alloc(&mem, sizeof(struct s2n_async_pkey_op)));
    GUARD_AS_RESULT(s2n_blob_zero(&mem));

    *op = (void *) mem.data;
    if (s2n_blob_init(&mem, NULL, 0) != S2N_SUCCESS) {
        *op = NULL;
        return S2N_RESULT_ERROR;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_decrypt(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                  struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete)
{
    ENSURE_REF(conn);
    ENSURE_REF(encrypted);
    ENSURE_REF(init_decrypted);
    ENSURE_REF(on_complete);

    if (conn->config->async_pkey_cb) {
        GUARD_RESULT(s2n_async_pkey_decrypt_async(conn, encrypted, init_decrypted, on_complete));
    } else {
        GUARD_RESULT(s2n_async_pkey_decrypt_sync(conn, encrypted, init_decrypted, on_complete));
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_decrypt_async(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                        struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete)
{
    ENSURE_REF(conn);
    ENSURE_REF(encrypted);
    ENSURE_REF(init_decrypted);
    ENSURE_REF(on_complete);
    ENSURE(conn->handshake.async_state == S2N_ASYNC_NOT_INVOKED, S2N_ERR_ASYNC_MORE_THAN_ONE);

    DEFER_CLEANUP(struct s2n_async_pkey_op *op = NULL, s2n_async_pkey_op_free_pointer);
    GUARD_RESULT(s2n_async_pkey_op_allocate(&op));

    op->type = S2N_ASYNC_DECRYPT;
    op->conn = conn;

    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;
    decrypt->on_complete                        = on_complete;

    GUARD_AS_RESULT(s2n_dup(encrypted, &decrypt->encrypted));
    GUARD_AS_RESULT(s2n_dup(init_decrypted, &decrypt->decrypted));

    /* Block the handshake and set async state to invoking to block async states */
    GUARD_AS_RESULT(s2n_conn_set_handshake_read_block(conn));
    conn->handshake.async_state = S2N_ASYNC_INVOKING_CALLBACK;

    /* Move op to tmp to avoid DEFER_CLEANUP freeing the op, as it will be owned by callback */
    struct s2n_async_pkey_op *tmp_op = op;
    op = NULL;

    ENSURE(conn->config->async_pkey_cb(conn, tmp_op) == S2N_SUCCESS, S2N_ERR_ASYNC_CALLBACK_FAILED);

    /* Set state to waiting to allow op to be consumed by connection */
    conn->handshake.async_state = S2N_ASYNC_INVOKED_WAITING;

    /* Return an async blocked error to drop out of s2n_negotiate loop */
    BAIL(S2N_ERR_ASYNC_BLOCKED);
}

S2N_RESULT s2n_async_pkey_decrypt_sync(struct s2n_connection *conn, struct s2n_blob *encrypted,
                                       struct s2n_blob *init_decrypted, s2n_async_pkey_decrypt_complete on_complete)
{
    ENSURE_REF(conn);
    ENSURE_REF(encrypted);
    ENSURE_REF(init_decrypted);
    ENSURE_REF(on_complete);

    const struct s2n_pkey *pkey = conn->handshake_params.our_chain_and_key->private_key;

    bool rsa_failed = s2n_pkey_decrypt(pkey, encrypted, init_decrypted) != S2N_SUCCESS;
    GUARD_AS_RESULT(on_complete(conn, rsa_failed, init_decrypted));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_sign(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                               struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete)
{
    ENSURE_REF(conn);
    ENSURE_REF(digest);
    ENSURE_REF(on_complete);

    if (conn->config->async_pkey_cb) {
        GUARD_RESULT(s2n_async_pkey_sign_async(conn, sig_alg, digest, on_complete));
    } else {
        GUARD_RESULT(s2n_async_pkey_sign_sync(conn, sig_alg, digest, on_complete));
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_sign_async(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                                     struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete)
{
    ENSURE_REF(conn);
    ENSURE_REF(digest);
    ENSURE_REF(on_complete);
    ENSURE(conn->handshake.async_state == S2N_ASYNC_NOT_INVOKED, S2N_ERR_ASYNC_MORE_THAN_ONE);

    DEFER_CLEANUP(struct s2n_async_pkey_op *op = NULL, s2n_async_pkey_op_free_pointer);
    GUARD_RESULT(s2n_async_pkey_op_allocate(&op));

    op->type = S2N_ASYNC_SIGN;
    op->conn = conn;

    struct s2n_async_pkey_sign_data *sign = &op->op.sign;
    sign->on_complete                     = on_complete;
    sign->sig_alg                         = sig_alg;

    GUARD_AS_RESULT(s2n_hash_new(&sign->digest));
    GUARD_AS_RESULT(s2n_hash_copy(&sign->digest, digest));

    /* Block the handshake and set async state to invoking to block async states */
    GUARD_AS_RESULT(s2n_conn_set_handshake_read_block(conn));
    conn->handshake.async_state = S2N_ASYNC_INVOKING_CALLBACK;

    /* Move op to tmp to avoid DEFER_CLEANUP freeing the op, as it will be owned by callback */
    struct s2n_async_pkey_op *tmp_op = op;
    op = NULL;

    ENSURE(conn->config->async_pkey_cb(conn, tmp_op) == S2N_SUCCESS, S2N_ERR_ASYNC_CALLBACK_FAILED);

    /* Set state to waiting to allow op to be consumed by connection */
    conn->handshake.async_state = S2N_ASYNC_INVOKED_WAITING;

    /* Return an async blocked error to drop out of s2n_negotiate loop */
    BAIL(S2N_ERR_ASYNC_BLOCKED);
}

S2N_RESULT s2n_async_pkey_sign_sync(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
                                    struct s2n_hash_state *digest, s2n_async_pkey_sign_complete on_complete)
{
    ENSURE_REF(conn);
    ENSURE_REF(digest);
    ENSURE_REF(on_complete);

    const struct s2n_pkey *pkey = conn->handshake_params.our_chain_and_key->private_key;
    DEFER_CLEANUP(struct s2n_blob signed_content = { 0 }, s2n_free);

    uint32_t maximum_signature_length = s2n_pkey_size(pkey);
    GUARD_AS_RESULT(s2n_alloc(&signed_content, maximum_signature_length));

    GUARD_AS_RESULT(s2n_pkey_sign(pkey, sig_alg, digest, &signed_content));

    GUARD_AS_RESULT(on_complete(conn, &signed_content));

    return S2N_RESULT_OK;
}

int s2n_async_pkey_op_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *key)
{
    ENSURE_POSIX_REF(op);
    ENSURE_POSIX_REF(key);
    ENSURE_POSIX(!op->complete, S2N_ERR_ASYNC_ALREADY_PERFORMED);

    const struct s2n_async_pkey_op_actions *actions = NULL;
    GUARD_AS_POSIX(s2n_async_get_actions(op->type, &actions));

    GUARD_AS_POSIX(actions->perform(op, key));

    op->complete = true;

    return S2N_SUCCESS;
}

int s2n_async_pkey_op_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn)
{
    ENSURE_POSIX_REF(op);
    ENSURE_POSIX_REF(conn);
    ENSURE_POSIX(op->complete, S2N_ERR_ASYNC_NOT_PERFORMED);
    ENSURE_POSIX(!op->applied, S2N_ERR_ASYNC_ALREADY_APPLIED);
    /* We could have just used op->conn and removed a conn argument, but we want caller
     * to be explicit about connection it wants to resume. Plus this gives more
     * protections in cases if caller frees connection object and then tries to resume
     * the connection. */
    ENSURE_POSIX(op->conn == conn, S2N_ERR_ASYNC_WRONG_CONNECTION);
    ENSURE_POSIX(conn->handshake.async_state != S2N_ASYNC_INVOKING_CALLBACK, S2N_ERR_ASYNC_APPLY_WHILE_INVOKING);
    ENSURE_POSIX(conn->handshake.async_state == S2N_ASYNC_INVOKED_WAITING, S2N_ERR_ASYNC_WRONG_CONNECTION);

    const struct s2n_async_pkey_op_actions *actions = NULL;
    GUARD_AS_POSIX(s2n_async_get_actions(op->type, &actions));

    GUARD_AS_POSIX(actions->apply(op, conn));

    op->applied                 = true;
    conn->handshake.async_state = S2N_ASYNC_INVOKED_COMPLETE;

    /* Free up the decrypt/sign structs to avoid storing secrets for too long */
    GUARD_AS_POSIX(actions->free(op));

    return S2N_SUCCESS;
}

int s2n_async_pkey_op_free(struct s2n_async_pkey_op *op)
{
    ENSURE_POSIX_REF(op);
    const struct s2n_async_pkey_op_actions *actions = NULL;
    GUARD_AS_POSIX(s2n_async_get_actions(op->type, &actions));

    /* If applied the decrypt/sign structs were released in apply call */
    if (!op->applied) { GUARD_AS_POSIX(actions->free(op)); }

    GUARD_POSIX(s2n_free_object(( uint8_t ** )&op, sizeof(struct s2n_async_pkey_op)));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_async_pkey_decrypt_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey)
{
    ENSURE_REF(op);
    ENSURE_REF(pkey);

    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;

    decrypt->rsa_failed = s2n_pkey_decrypt(pkey, &decrypt->encrypted, &decrypt->decrypted) != S2N_SUCCESS;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_decrypt_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn)
{
    ENSURE_REF(op);
    ENSURE_REF(conn);

    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;

    GUARD_AS_RESULT(decrypt->on_complete(conn, decrypt->rsa_failed, &decrypt->decrypted));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_decrypt_free(struct s2n_async_pkey_op *op)
{
    ENSURE_REF(op);

    struct s2n_async_pkey_decrypt_data *decrypt = &op->op.decrypt;

    GUARD_AS_RESULT(s2n_blob_zero(&decrypt->decrypted));
    GUARD_AS_RESULT(s2n_blob_zero(&decrypt->encrypted));
    GUARD_AS_RESULT(s2n_free(&decrypt->decrypted));
    GUARD_AS_RESULT(s2n_free(&decrypt->encrypted));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_sign_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *pkey)
{
    ENSURE_REF(op);
    ENSURE_REF(pkey);

    struct s2n_async_pkey_sign_data *sign = &op->op.sign;

    uint32_t maximum_signature_length = s2n_pkey_size(pkey);
    GUARD_AS_RESULT(s2n_alloc(&sign->signature, maximum_signature_length));

    GUARD_AS_RESULT(s2n_pkey_sign(pkey, sign->sig_alg, &sign->digest, &sign->signature));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_sign_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn)
{
    ENSURE_REF(op);
    ENSURE_REF(conn);

    struct s2n_async_pkey_sign_data *sign = &op->op.sign;

    GUARD_AS_RESULT(sign->on_complete(conn, &sign->signature));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_async_pkey_sign_free(struct s2n_async_pkey_op *op)
{
    ENSURE_REF(op);

    struct s2n_async_pkey_sign_data *sign = &op->op.sign;

    GUARD_AS_RESULT(s2n_hash_free(&sign->digest));
    GUARD_AS_RESULT(s2n_free(&sign->signature));

    return S2N_RESULT_OK;
}
