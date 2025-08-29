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
#include "tls/s2n_async_offload.h"

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

S2N_RESULT s2n_async_offload_cb_invoke(struct s2n_connection *conn, struct s2n_async_op *op)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(op);
    RESULT_ENSURE_REF(op->perform);
    RESULT_ENSURE(op->async_state == S2N_ASYNC_NOT_INVOKED, S2N_ERR_ASYNC_MORE_THAN_ONE);
    RESULT_ENSURE_REF(conn->config->async_offload_cb);

    op->async_state = S2N_ASYNC_INVOKED;
    RESULT_ENSURE(conn->config->async_offload_cb(conn, op, conn->config->async_offload_ctx) == S2N_SUCCESS,
            S2N_ERR_CANCELLED);

    /*
     * If the callback already completed the operation, continue.
     * Otherwise, we need to block s2n_negotiate and wait for the operation to complete.
     */
    if (op->async_state == S2N_ASYNC_COMPLETE) {
        return S2N_RESULT_OK;
    }
    RESULT_BAIL(S2N_ERR_ASYNC_BLOCKED);
}

int s2n_async_op_perform(struct s2n_async_op *op)
{
    POSIX_ENSURE_REF(op);
    POSIX_ENSURE(!op->perform_invoked, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE(op->async_state == S2N_ASYNC_INVOKED, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE(op->type != S2N_ASYNC_OP_NONE, S2N_ERR_INVALID_STATE);

    POSIX_ENSURE_REF(op->conn);
    POSIX_ENSURE_REF(op->perform);
    op->perform_invoked = true;

    POSIX_GUARD_RESULT(op->perform(op));
    op->async_state = S2N_ASYNC_COMPLETE;
    return S2N_SUCCESS;
}

/**
 * MUST be called at the end of each handshake state handler that may invoke async_offload_cb
 * to clean up the op object and async state.
 */
S2N_RESULT s2n_async_op_wipe(struct s2n_async_op *op, s2n_async_op_type expected_type)
{
    RESULT_ENSURE_REF(op);
    /* Sync case: async_offload_cb not invoked in the current state */
    if (op->async_state == S2N_ASYNC_NOT_INVOKED) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE_EQ(op->type, expected_type);
    RESULT_ENSURE(op->async_state == S2N_ASYNC_COMPLETE, S2N_ERR_INVALID_STATE);
    RESULT_CHECKED_MEMSET(op, 0, sizeof(struct s2n_async_op));

    return S2N_RESULT_OK;
}

bool s2n_async_is_op_in_allow_list(struct s2n_config *config, s2n_async_op_type op_type)
{
    return config && (config->async_offload_allow_list & op_type);
}
