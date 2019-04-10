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

int s2n_server_cert_recv(struct s2n_connection *conn)
{
    uint32_t size_of_all_certificates;
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &size_of_all_certificates));

    S2N_ERROR_IF(size_of_all_certificates > s2n_stuffer_data_available(&conn->handshake.io) || size_of_all_certificates < 3, S2N_ERR_BAD_MESSAGE);

    s2n_cert_public_key public_key;
    GUARD(s2n_pkey_zero_init(&public_key));

    s2n_cert_type actual_cert_type;
    struct s2n_blob cert_chain = {0};
    cert_chain.data = s2n_stuffer_raw_read(&conn->handshake.io, size_of_all_certificates);
    cert_chain.size = size_of_all_certificates;

    S2N_ERROR_IF(s2n_x509_validator_validate_cert_chain(&conn->x509_validator, conn, cert_chain.data,
                         cert_chain.size, &actual_cert_type, &public_key) != S2N_CERT_OK, S2N_ERR_CERT_UNTRUSTED);

    s2n_authentication_method expected_auth_method = conn->secure.cipher_suite->auth_method;

    switch (actual_cert_type) {
    case S2N_CERT_TYPE_RSA_SIGN:
        S2N_ERROR_IF(expected_auth_method != S2N_AUTHENTICATION_RSA, S2N_ERR_CERT_TYPE_UNSUPPORTED);
        break;
    case S2N_CERT_TYPE_ECDSA_SIGN:
        S2N_ERROR_IF(expected_auth_method != S2N_AUTHENTICATION_ECDSA, S2N_ERR_CERT_TYPE_UNSUPPORTED);
        break;
    default:
        S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
    }
    
    conn->secure.client_cert_type = actual_cert_type;
    s2n_pkey_setup_for_type(&public_key, actual_cert_type);
    conn->secure.server_public_key = public_key;
    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn)
{
    GUARD(s2n_send_cert_chain(&conn->handshake.io, conn->handshake_params.our_chain_and_key->cert_chain));
    return 0;
}
