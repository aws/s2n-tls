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
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This is a special value assigned to handshake_start_epoch_ns to indicate that
 * it has already been sent to the application and should not be sent again.
 */
#define HANDSHAKE_EVENT_SENT UINT64_C(1) << 63

struct s2n_event_handshake {
    /**
     * The negotiated protocol version
     * 
     * This will be one of the protocol version constants defined in s2n.h 
     */
    int protocol_version;
    /* static memory */
    const char *cipher;
    /* static memory */
    const char *group;
    /* static memory */
    const char *security_policy_label;
    /* the amount of time inside the synchronous s2n_negotiate method */
    uint64_t handshake_time_ns;
    /**
     * The start of the handshake. This is not an interpretable time, and only has
     * meaning in reference to handshake_end_ns. 
     *
     * This is also used as a flag to ensure that the same event isn't emitted 
     * twice. After the event has been emitted this is set to HANDSHAKE_EVENT_SENT
     */
    uint64_t handshake_start_ns;
    uint64_t handshake_end_ns;
    /**
     * If the handshake failed, this contains the error code.
     * 0 indicates no error (successful handshake).
     * The error name can be retrieved via s2n_strerror_name(error_code).
     */
    int error_code;
};

typedef void (*s2n_event_on_handshake_cb)(struct s2n_connection *conn, void *subscriber, struct s2n_event_handshake *event);

S2N_API extern int s2n_config_set_subscriber(struct s2n_config *config, void *subscriber);
/**
 * Set a callback to receive a handshake event.
 * 
 * The `struct s2n_event_handshake *event` is only valid over the lifetime of the 
 * callbacks, and must not be referenced after the callback returned.
 * 
 * An event is emitted both on success and failure. On failure, the event's
 * error_code field will be set with the relevant error information.
 */
S2N_API extern int s2n_config_set_handshake_event(struct s2n_config *config, s2n_event_on_handshake_cb callback);

/**
 * Per-message timing checkpoint emitted once when each handshake message
 * handler finishes. Consumers reconstruct per-message durations by computing
 * the delta between consecutive checkpoint timestamps.
 *
 * Checkpoints fire from the shared handshake dispatch loop, so they are emitted
 * for every negotiated protocol version. The message names reflect whichever
 * version was negotiated.
 *
 * The pointer passed to the callback is valid only for the duration of the
 * callback invocation. Callers must copy any fields they want to retain.
 */
struct s2n_timing_checkpoint {
    /* Static-lifetime string identifying which message just finished. Points
     * into a `const char *[]` array, so the pointer itself is safe to read
     * during the callback. Do not retain the pointer past the callback. */
    const char *name;
    /* 0 = S2N_SERVER, 1 = S2N_CLIENT — matches conn->mode */
    uint8_t role;
    /* Monotonic timestamp in nanoseconds, captured via the same clock used
     * for handshake_start_ns / handshake_end_ns in struct s2n_event_handshake.
     * Per-message checkpoints and total handshake time are therefore on the
     * same timeline. */
    uint64_t timestamp_ns;
};

typedef void (*s2n_event_on_timing_checkpoint_cb)(struct s2n_connection *conn, void *subscriber, struct s2n_timing_checkpoint *checkpoint);

/**
 * Register a per-message timing checkpoint callback on a config.
 *
 * The callback fires once after each TLS handshake message handler completes,
 * with a single monotonic timestamp. The consumer reconstructs per-message
 * durations by computing deltas between consecutive checkpoint timestamps.
 *
 * The same `subscriber` pointer set via s2n_config_set_subscriber is passed
 * as the second argument to the callback. If no subscriber has been set,
 * NULL is passed.
 *
 * Note: On a server using SNI-based config swap (s2n_connection_set_config
 * called from the client hello callback), NEGOTIATE_START fires before the
 * swap occurs. To receive NEGOTIATE_START, register this callback on the
 * initial/default config, not only on the SNI-selected config.
 *
 * Returns S2N_SUCCESS on success.
 * Returns S2N_FAILURE with S2N_ERR_NULL if config or callback is NULL.
 */
S2N_API extern int s2n_config_set_timing_checkpoint_cb(struct s2n_config *config, s2n_event_on_timing_checkpoint_cb callback);

#ifdef __cplusplus
}
#endif
