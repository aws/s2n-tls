/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>

#include "crypto/s2n_certificate.h"
#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

static int inline is_cert_supported(struct s2n_connection *conn, s2n_pkey_type actual_cert_type)
{
    if (conn->actual_protocol_version == S2N_TLS13) {
        /* in TLS 1.3, the ciphersuite's auth_method
         * S2N_AUTHENTICATION_METHOD_TLS13 allows RSA and ECDSA certs */
        switch (actual_cert_type) {
        case S2N_PKEY_TYPE_RSA:
        case S2N_PKEY_TYPE_RSA_PSS:
        case S2N_PKEY_TYPE_ECDSA:
            break;
        default:
            S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
        }
    } else {
        s2n_authentication_method expected_auth_method = conn->secure.cipher_suite->auth_method;
        switch (actual_cert_type) {
        case S2N_PKEY_TYPE_RSA:
            S2N_ERROR_IF(expected_auth_method != S2N_AUTHENTICATION_RSA, S2N_ERR_CERT_TYPE_UNSUPPORTED);
            break;
        case S2N_PKEY_TYPE_RSA_PSS:
            S2N_ERROR_IF(expected_auth_method != S2N_AUTHENTICATION_RSA_PSS, S2N_ERR_CERT_TYPE_UNSUPPORTED);
            break;
        case S2N_PKEY_TYPE_ECDSA:
            S2N_ERROR_IF(expected_auth_method != S2N_AUTHENTICATION_ECDSA, S2N_ERR_CERT_TYPE_UNSUPPORTED);
            break;
        default:
            S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
        }
    }

    return S2N_SUCCESS;
}

int s2n_server_cert_recv(struct s2n_connection *conn)
{
    if (conn->actual_protocol_version == S2N_TLS13) {
        uint8_t certificate_request_context_len;
        GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, &certificate_request_context_len));
    }

    uint32_t size_of_all_certificates;
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &size_of_all_certificates));

    S2N_ERROR_IF(size_of_all_certificates > s2n_stuffer_data_available(&conn->handshake.io) || size_of_all_certificates < 3, S2N_ERR_BAD_MESSAGE);

    s2n_cert_public_key public_key;
    GUARD(s2n_pkey_zero_init(&public_key));

    s2n_pkey_type actual_cert_pkey_type;
    struct s2n_blob cert_chain = {0};
    cert_chain.size = size_of_all_certificates;
    cert_chain.data = s2n_stuffer_raw_read(&conn->handshake.io, size_of_all_certificates);
    notnull_check(cert_chain.data);

    S2N_ERROR_IF(s2n_x509_validator_validate_cert_chain(&conn->x509_validator, conn, cert_chain.data,
                         cert_chain.size, &actual_cert_pkey_type, &public_key) != S2N_CERT_OK, S2N_ERR_CERT_UNTRUSTED);

    GUARD(is_cert_supported(conn, actual_cert_pkey_type));
    GUARD(s2n_pkey_setup_for_type(&public_key, actual_cert_pkey_type));
    conn->secure.server_public_key = public_key;

    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn)
{
    if (conn->actual_protocol_version == S2N_TLS13) {
        /* server's certificate request context should always be of zero length */
        /* https://tools.ietf.org/html/rfc8446#section-4.4.2*/
        uint8_t certificate_request_context_len = 0;
        GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, certificate_request_context_len));
    }

    GUARD(s2n_send_cert_chain(&conn->handshake.io, conn->handshake_params.our_chain_and_key->cert_chain, conn->actual_protocol_version));

    return 0;
}
