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

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_x509_validator.h"
#include "tls/extensions/s2n_server_certificate_status.h"
#include "utils/s2n_safety.h"

#define U24_SIZE 3

/* In TLS 1.3, a response to a Status Request extension is sent as an extension with
 * status request as well as the OCSP response. This contrasts to TLS 1.2 where
 * the OCSP response is sent in the Certificate Status handshake message */

static bool s2n_tls13_server_status_request_should_send(struct s2n_connection *conn);

const s2n_extension_type s2n_tls13_server_status_request_extension = {
    .iana_value = TLS_EXTENSION_STATUS_REQUEST,
    .is_response = true,
    .send = s2n_server_certificate_status_send,
    .recv = s2n_server_certificate_status_recv,
    .should_send = s2n_tls13_server_status_request_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_tls13_server_status_request_should_send(struct s2n_connection *conn)
{
    return s2n_server_can_send_ocsp(conn);
}

int s2n_server_certificate_status_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    struct s2n_blob *ocsp_status = &conn->handshake_params.our_chain_and_key->ocsp_status;
    POSIX_ENSURE_REF(ocsp_status);

    POSIX_GUARD(s2n_stuffer_write_uint8(out, (uint8_t) S2N_STATUS_REQUEST_OCSP));
    POSIX_GUARD(s2n_stuffer_write_uint24(out, ocsp_status->size));
    POSIX_GUARD(s2n_stuffer_write(out, ocsp_status));

    return S2N_SUCCESS;
}

int s2n_server_certificate_status_recv(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    POSIX_ENSURE_REF(conn);

    uint8_t type;
    POSIX_GUARD(s2n_stuffer_read_uint8(in, &type));
    if (type != S2N_STATUS_REQUEST_OCSP) {
        /* We only support OCSP */
        return S2N_SUCCESS;
    }

    uint32_t status_size;
    POSIX_GUARD(s2n_stuffer_read_uint24(in, &status_size));
    POSIX_ENSURE_LTE(status_size, s2n_stuffer_data_available(in));

    POSIX_GUARD(s2n_realloc(&conn->status_response, status_size));
    POSIX_GUARD(s2n_stuffer_read_bytes(in, conn->status_response.data, status_size));

    POSIX_GUARD(s2n_x509_validator_validate_cert_stapled_ocsp_response(
            &conn->x509_validator, conn, conn->status_response.data, conn->status_response.size));

    return S2N_SUCCESS;
}
