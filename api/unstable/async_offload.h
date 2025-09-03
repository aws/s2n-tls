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

#pragma once

#include <s2n.h>

/**
 * @file async_offload.h
 * 
 * The following APIs enable applications to offload expensive handshake operations that do not require user input.
 * Use s2n_config_set_async_offload_callback() to configure the async callback and the set of operations to offload.
 * 
 * `s2n_negotiate()` will throw an `S2N_ERR_T_BLOCKED` error if the handshake is blocked by the offloading callback.
 * s2n_async_op_perform() must be invoked to unblock the handshake.
 */

/**
 * Opaque struct for the async offloading operation
 */
struct s2n_async_op;

/**
 * The type of operations supported by the async offloading callback. Each type is represented by a different bit.
 * 
 * WARNING: S2N_ASYNC_ALLOW_ALL will automatically opt in to all the new types added in the future.
 */
typedef enum {
    S2N_ASYNC_OP_NONE = 0,
    S2N_ASYNC_PKEY_VERIFY = 0x01,
    S2N_ASYNC_ALLOW_ALL = 0x7FFFFFFF,
} s2n_async_op_type;

/**
 * The callback function invoked every time an allowed async operation is encountered during the handshake.
 * 
 * To perform an operation asynchronously, the following condiditions must be satisfied:
 * 1) This op type must be included in the allow list;
 * 2) Async offloading callback returns success and s2n_async_op_perform() is invoked outside the callback.
 *
 * If s2n_async_op_perform() is invoked inside the callback, it is equivalent to the synchronous use case.
 * 
 * `op` is owned by s2n-tls and op data will be freed in the call to `s2n_async_op_perform()`.
 *
 * @param conn Connection which triggered the async offloading callback
 * @param op An opaque object representing the async operation
 * @param ctx Application data provided to the callback via s2n_config_set_async_offload_callback()
 */
typedef int (*s2n_async_offload_cb)(struct s2n_connection *conn, struct s2n_async_op *op, void *ctx);

/**
 * Sets up the async callback to offload handshake operations configured via the allow_list.
 * 
 * The default allow list for s2n_config is S2N_ASYNC_OP_NONE.
 *
 * @param config Config to set the callback
 * @param fn The function that should be called for each allowed async operation
 * @param allow_list A bit representation of allowed operations (Bit-OR of all the allowd s2n_async_op_type values)
 * @param ctx Optional application data passed to the callback
 */
S2N_API extern int s2n_config_set_async_offload_callback(struct s2n_config *config, s2n_async_offload_cb fn,
        uint32_t allow_list, void *ctx);

/**
 * Performs the operation triggered by the async offloading callback.
 * 
 * op_perform() can only be called once for each triggered operation.
 * 
 * @param op An opaque object representing the async operation
 */
S2N_API extern int s2n_async_op_perform(struct s2n_async_op *op);
