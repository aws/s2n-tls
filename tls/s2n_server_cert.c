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
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_server_cert_recv(struct s2n_connection *conn)
{
    uint32_t size_of_all_certificates;

    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &size_of_all_certificates));

    if (size_of_all_certificates > s2n_stuffer_data_available(&conn->handshake.io) || size_of_all_certificates < 3) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    s2n_cert_public_key public_key;
    s2n_cert_type cert_type;
    struct s2n_blob cert_chain;
    cert_chain.data = s2n_stuffer_raw_read(&conn->handshake.io, size_of_all_certificates);
    cert_chain.size = size_of_all_certificates;

    const s2n_cert_validation_code rc = conn->config->verify_cert_chain_cb(conn, cert_chain.data, cert_chain.size, &cert_type, &public_key, conn->config->verify_cert_context);

    if (rc != S2N_CERT_OK) {
        S2N_ERROR(S2N_ERR_CERT_UNTRUSTED);
    }

    if(cert_type != S2N_CERT_TYPE_RSA_SIGN) {
        S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    }

    /* We know it's an RSA Key, verify it isn't null. */
    GUARD(s2n_rsa_check_key_exists(&public_key));

    /* Init pkey function pointers for this Cert Type for when it will be verified. */
    GUARD(s2n_pkey_setup_for_type(&public_key, cert_type));

    conn->secure.server_public_key = public_key;

    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn)
{
    GUARD(s2n_send_cert_chain(&conn->handshake.io, &conn->server->server_cert_chain->cert_chain));
    return 0;
}
