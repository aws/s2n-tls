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

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

/* Store the raw server certificate chain for later retrieval via
 * s2n_connection_get_unverified_peer_cert_chain().
 *
 * This mirrors the approach used for client certificates in
 * s2n_client_cert_chain_store(). For TLS 1.3, the per-certificate
 * extensions are stripped so the returned format matches TLS 1.2:
 * each certificate is a DER-encoded ASN.1 X.509 prepended by a
 * 3-byte network-endian length.
 */
static S2N_RESULT s2n_server_cert_chain_store(struct s2n_connection *conn,
        struct s2n_blob *raw_cert_chain)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(raw_cert_chain);

    /* If a server cert chain has already been stored (e.g. on the re-entry case
     * of an async callback), no need to store it again.
     */
    if (conn->handshake_params.server_cert_chain.size > 0) {
        return S2N_RESULT_OK;
    }

    /* Earlier versions are a basic copy */
    if (conn->actual_protocol_version < S2N_TLS13) {
        RESULT_GUARD_POSIX(s2n_dup(raw_cert_chain, &conn->handshake_params.server_cert_chain));
        return S2N_RESULT_OK;
    }

    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_realloc(&output, raw_cert_chain->size));

    struct s2n_stuffer cert_chain_in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&cert_chain_in, raw_cert_chain));

    struct s2n_stuffer cert_chain_out = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&cert_chain_out, &output));

    uint32_t cert_size = 0;
    uint16_t extensions_size = 0;
    while (s2n_stuffer_data_available(&cert_chain_in)) {
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(&cert_chain_in, &cert_size));
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(&cert_chain_out, cert_size));
        RESULT_GUARD_POSIX(s2n_stuffer_copy(&cert_chain_in, &cert_chain_out, cert_size));

        /* The TLS1.3 format includes per-certificate extensions, which we must skip.
         * Customers will not expect TLS extensions in a DER-encoded certificate.
         */
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&cert_chain_in, &extensions_size));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&cert_chain_in, extensions_size));
    }

    output.size = s2n_stuffer_data_available(&cert_chain_out);

    conn->handshake_params.server_cert_chain = output;
    ZERO_TO_DISABLE_DEFER_CLEANUP(output);
    return S2N_RESULT_OK;
}

int s2n_server_cert_recv(struct s2n_connection *conn)
{
    /* s2n_server_cert_recv() may be re-entered due to handling an async callback.
     * We operate on a copy of `handshake.io` to ensure the stuffer is initilized properly on the re-entry case.
     */
    struct s2n_stuffer in = conn->handshake.io;

    if (conn->actual_protocol_version == S2N_TLS13) {
        uint8_t certificate_request_context_len = 0;
        POSIX_GUARD(s2n_stuffer_read_uint8(&in, &certificate_request_context_len));
        S2N_ERROR_IF(certificate_request_context_len != 0, S2N_ERR_BAD_MESSAGE);
    }

    uint32_t size_of_all_certificates = 0;
    POSIX_GUARD(s2n_stuffer_read_uint24(&in, &size_of_all_certificates));

    S2N_ERROR_IF(size_of_all_certificates > s2n_stuffer_data_available(&in) || size_of_all_certificates < 3,
            S2N_ERR_BAD_MESSAGE);

    DEFER_CLEANUP(s2n_cert_public_key public_key = { 0 }, s2n_pkey_free);
    POSIX_GUARD(s2n_pkey_zero_init(&public_key));

    s2n_pkey_type actual_cert_pkey_type;
    struct s2n_blob cert_chain = { 0 };
    cert_chain.size = size_of_all_certificates;
    cert_chain.data = s2n_stuffer_raw_read(&in, size_of_all_certificates);
    POSIX_ENSURE_REF(cert_chain.data);

    /* Store the raw certificate chain before validation so that it can be
     * retrieved even if validation fails. This enables callers to inspect
     * the server's certificate for diagnostics/logging on handshake failure.
     */
    POSIX_ENSURE(s2n_result_is_ok(s2n_server_cert_chain_store(conn, &cert_chain)),
            S2N_ERR_BAD_MESSAGE);

    POSIX_GUARD_RESULT(s2n_x509_validator_validate_cert_chain(&conn->x509_validator, conn, cert_chain.data,
            cert_chain.size, &actual_cert_pkey_type, &public_key));

    POSIX_GUARD(s2n_is_cert_type_valid_for_auth(conn, actual_cert_pkey_type));
    POSIX_GUARD_RESULT(s2n_pkey_setup_for_type(&public_key, actual_cert_pkey_type));
    conn->handshake_params.server_public_key = public_key;
    ZERO_TO_DISABLE_DEFER_CLEANUP(public_key);

    /* Update handshake.io to reflect the true stuffer state after all async callbacks are handled. */
    conn->handshake.io = in;

    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn)
{
    S2N_ERROR_IF(conn->handshake_params.our_chain_and_key == NULL, S2N_ERR_CERT_TYPE_UNSUPPORTED);
    if (conn->actual_protocol_version == S2N_TLS13) {
        /* server's certificate request context should always be of zero length */
        /* https://tools.ietf.org/html/rfc8446#section-4.4.2 */
        uint8_t certificate_request_context_len = 0;
        POSIX_GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, certificate_request_context_len));
    }

    POSIX_GUARD(s2n_send_cert_chain(conn, &conn->handshake.io, conn->handshake_params.our_chain_and_key));

    return 0;
}
