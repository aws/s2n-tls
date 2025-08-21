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
#include "tls/s2n_async_generic.h"

#include "api/s2n.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"
#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

static S2N_RESULT s2n_async_op_allocate(struct s2n_async_op **op)
{
    RESULT_ENSURE_REF(op);
    RESULT_ENSURE(*op == NULL, S2N_ERR_SAFETY);

    /* allocate memory */
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_async_op)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&mem));

    *op = (void *) mem.data;
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_async_generic_cb_invoke(struct s2n_connection *conn, struct s2n_async_op **op_ptr)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(op_ptr);
    RESULT_ENSURE(conn->handshake.async_state == S2N_ASYNC_NOT_INVOKED, S2N_ERR_ASYNC_MORE_THAN_ONE);

    struct s2n_async_op *op = *op_ptr;
    ZERO_TO_DISABLE_DEFER_CLEANUP(*op_ptr);

    conn->handshake.async_state = S2N_ASYNC_INVOKED;
    RESULT_ENSURE(conn->config->generic_async_cb(conn, op, conn->config->async_cb_ctx) == S2N_SUCCESS,
            S2N_ERR_ASYNC_CALLBACK_FAILED);

    /*
     * If the callback already completed the operation, continue.
     * Otherwise, we need to block s2n_negotiate and wait for the operation to complete.
     */
    if (conn->handshake.async_state == S2N_ASYNC_COMPLETE) {
        return S2N_RESULT_OK;
    }
    RESULT_BAIL(S2N_ERR_ASYNC_BLOCKED);
}

static int s2n_async_op_free(struct s2n_async_op **op_ptr)
{
    POSIX_ENSURE_REF(op_ptr);

    POSIX_GUARD(s2n_free_object((uint8_t **) op_ptr, sizeof(struct s2n_async_op)));

    return S2N_SUCCESS;
}

int s2n_async_op_perform(struct s2n_async_op *op)
{
    POSIX_ENSURE_REF(op);
    POSIX_ENSURE(op->type != NO_OP, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE_REF(op->conn);
    POSIX_ENSURE(op->conn->handshake.async_state == S2N_ASYNC_INVOKED, S2N_ERR_INVALID_STATE);

    POSIX_ENSURE_REF(op->perform);
    POSIX_GUARD_RESULT(op->perform(op));
    op->conn->handshake.async_state = S2N_ASYNC_COMPLETE;
    op->type = NO_OP;

    POSIX_GUARD(s2n_async_op_free(&op));
    POSIX_ENSURE_EQ(op, NULL);
    return S2N_SUCCESS;
}

bool s2n_async_is_op_in_allow_list(struct s2n_config *config, s2n_async_op_type op_type)
{
    return config->async_allow_list & op_type;
}

static S2N_RESULT s2n_async_pkey_verify_perform(struct s2n_async_op *op)
{
    RESULT_ENSURE_REF(op);
    RESULT_ENSURE(op->type == S2N_ASYNC_VERIFY, S2N_ERR_INVALID_ARGUMENT);

    struct s2n_async_pkey_verify_data *verify = &op->op_data.verify;
    RESULT_ENSURE(s2n_pkey_verify(verify->pub_key, verify->sig_alg, &verify->digest, &verify->signature) == S2N_SUCCESS,
            S2N_ERR_VERIFY_SIGNATURE);

    /* Free the memory allocated for s2n_async_pkey_verify_data to prevent memory leak. */
    RESULT_GUARD_POSIX(s2n_hash_free(&verify->digest));
    RESULT_GUARD_POSIX(s2n_free(&verify->signature));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_async_pkey_verify_async(struct s2n_connection *conn, struct s2n_pkey *pub_key,
        s2n_signature_algorithm sig_alg, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(digest);
    RESULT_ENSURE_REF(signature);

    // struct s2n_async_op *op = &conn->op;
    DEFER_CLEANUP(struct s2n_async_op *op = NULL, s2n_async_op_free);
    RESULT_GUARD(s2n_async_op_allocate(&op));

    op->conn = conn;
    op->type = S2N_ASYNC_VERIFY;
    op->perform = s2n_async_pkey_verify_perform;

    struct s2n_async_pkey_verify_data *verify = &op->op_data.verify;
    verify->pub_key = pub_key;
    verify->sig_alg = sig_alg;

    RESULT_GUARD_POSIX(s2n_hash_new(&verify->digest));
    RESULT_GUARD_POSIX(s2n_hash_copy(&verify->digest, digest));
    RESULT_GUARD_POSIX(s2n_dup(signature, &verify->signature));

    RESULT_GUARD(s2n_async_generic_cb_invoke(conn, &op));
    return S2N_RESULT_OK;
}

int s2n_async_pkey_verify(struct s2n_connection *conn, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(digest);
    POSIX_ENSURE_REF(signature);

    struct s2n_pkey *pub_key = NULL;
    if (conn->mode == S2N_CLIENT) {
        pub_key = &conn->handshake_params.server_public_key;
    } else {
        pub_key = &conn->handshake_params.client_public_key;
    }

    if (s2n_async_is_op_in_allow_list(conn->config, S2N_ASYNC_VERIFY)) {
        POSIX_GUARD_RESULT(s2n_async_pkey_verify_async(conn, pub_key, sig_alg, digest, signature));
    } else {
        POSIX_GUARD(s2n_pkey_verify(pub_key, sig_alg, digest, signature));
    }

    return S2N_SUCCESS;
}
