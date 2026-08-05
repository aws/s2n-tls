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

#include "utils/s2n_events.h"

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"

/**
 * Populate handshake information at the end of the handshake.
 * 
 * Precondition: handshake timing information is already completed
 */
S2N_RESULT s2n_event_handshake_populate(struct s2n_connection *conn, struct s2n_event_handshake *event)
{
    RESULT_ENSURE_REF(event);

    event->protocol_version = s2n_connection_get_actual_protocol_version(conn);
    event->cipher = s2n_connection_get_cipher(conn);
    /* get_key_group is expected to fail in cases where a group is not negotiated,
     * e.g. RSA key exchange. In this case event->group will be null. */
    s2n_connection_get_key_exchange_group(conn, &event->group);

    const struct s2n_security_policy *security_policy = NULL;
    if (s2n_connection_get_security_policy(conn, &security_policy) == S2N_SUCCESS) {
        event->security_policy_label = s2n_find_version_from_security_policy(security_policy);
    }

    return S2N_RESULT_OK;
}

/**
 * Send the completed handshake event by calling the appropriate method
 * on the subscriber.
 * 
 * If there is no subscriber on the config this method is a no-op
 */
S2N_RESULT s2n_event_handshake_send(struct s2n_connection *conn, struct s2n_event_handshake *event)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);
    RESULT_ENSURE_REF(event);

    if (conn->config->subscriber == NULL || conn->config->on_handshake_event == NULL) {
        return S2N_RESULT_OK;
    }

    /* the event has already been sent */
    if (event->handshake_start_ns == HANDSHAKE_EVENT_SENT) {
        return S2N_RESULT_OK;
    }

    conn->config->on_handshake_event(conn, conn->config->subscriber, event);
    event->handshake_start_ns = HANDSHAKE_EVENT_SENT;
    return S2N_RESULT_OK;
}

/**
 * Emit a per-message timing checkpoint.
 *
 * No-op if no callback is registered or config is NULL.
 */
S2N_RESULT s2n_event_checkpoint_send(struct s2n_connection *conn, const char *name, uint8_t role)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(name);

    if (conn->config == NULL || conn->config->on_timing_checkpoint_cb == NULL) {
        return S2N_RESULT_OK;
    }

    uint64_t timestamp_ns = 0;
    RESULT_GUARD_POSIX(s2n_default_monotonic_clock(NULL, &timestamp_ns));

    struct s2n_timing_checkpoint checkpoint = {
        .name = name,
        .role = role,
        .timestamp_ns = timestamp_ns,
    };

    conn->config->on_timing_checkpoint_cb(conn, conn->config->subscriber, &checkpoint);
    return S2N_RESULT_OK;
}
