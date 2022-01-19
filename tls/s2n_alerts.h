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

#include <stdint.h>

#include "tls/s2n_connection.h"

typedef enum {
    S2N_TLS_ALERT_CLOSE_NOTIFY = 0,
    S2N_TLS_ALERT_UNEXPECTED_MESSAGE = 10,
    S2N_TLS_ALERT_BAD_RECORD_MAC = 20,
    S2N_TLS_ALERT_RECORD_OVERFLOW = 22,
    S2N_TLS_ALERT_HANDSHAKE_FAILURE = 40,
    S2N_TLS_ALERT_BAD_CERTIFICATE = 42,
    S2N_TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43,
    S2N_TLS_ALERT_CERTIFICATE_REVOKED = 44,
    S2N_TLS_ALERT_CERTIFICATE_EXPIRED = 45,
    S2N_TLS_ALERT_CERTIFICATE_UNKNOWN = 46,
    S2N_TLS_ALERT_ILLEGAL_PARAMETER = 47,
    S2N_TLS_ALERT_UNKNOWN_CA = 48,
    S2N_TLS_ALERT_ACCESS_DENIED = 49,
    S2N_TLS_ALERT_DECODE_ERROR = 50,
    S2N_TLS_ALERT_DECRYPT_ERROR = 51,
    S2N_TLS_ALERT_PROTOCOL_VERSION = 70,
    S2N_TLS_ALERT_INSUFFICIENT_SECURITY = 71,
    S2N_TLS_ALERT_INTERNAL_ERROR = 80,
    S2N_TLS_ALERT_INAPPROPRIATE_FALLBACK = 86,
    S2N_TLS_ALERT_USER_CANCELED = 90,
    S2N_TLS_ALERT_MISSING_EXTENSION = 109,
    S2N_TLS_ALERT_UNSUPPORTED_EXTENSION = 110,
    S2N_TLS_ALERT_UNRECOGNIZED_NAME = 112,
    S2N_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    S2N_TLS_ALERT_UNKNOWN_PSK_IDENTITY = 115,
    S2N_TLS_ALERT_CERTIFICATE_REQUIRED = 116,
    S2N_TLS_ALERT_NO_APPLICATION_PROTOCOL = 120,
} s2n_tls_alert_code;

extern int s2n_process_alert_fragment(struct s2n_connection *conn);
extern int s2n_queue_writer_close_alert_warning(struct s2n_connection *conn);
extern int s2n_queue_reader_unsupported_protocol_version_alert(struct s2n_connection *conn);
extern int s2n_queue_reader_handshake_failure_alert(struct s2n_connection *conn);
