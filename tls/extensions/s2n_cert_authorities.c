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
#include "tls/extensions/s2n_cert_authorities.h"

#include "utils/s2n_safety.h"

int s2n_cert_authorities_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_EQ(conn->mode, S2N_SERVER);
    struct s2n_blob *cert_authorities = &conn->config->cert_authorities;
    POSIX_GUARD(s2n_stuffer_write_uint16(out, cert_authorities->size));
    POSIX_GUARD(s2n_stuffer_write(out, cert_authorities));
    return S2N_SUCCESS;
}

static bool s2n_cert_authorities_should_send(struct s2n_connection *conn)
{
    return conn && conn->config && conn->config->cert_authorities.size > 0;
}

const s2n_extension_type s2n_cert_authorities_extension = {
    .iana_value = TLS_EXTENSION_CERT_AUTHORITIES,
    .minimum_version = S2N_TLS13,
    .is_response = false,
    .send = s2n_cert_authorities_send,
    .should_send = s2n_cert_authorities_should_send,
    /* s2n-tls supports sending the extension, but does not support parsing it.
     * If received, the extension is ignored.
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.4
     *= type=exception
     *= reason=Extension ignored when received - No customer use case
     *# The "certificate_authorities" extension is used to indicate the
     *# certificate authorities (CAs) which an endpoint supports and which
     *# SHOULD be used by the receiving endpoint to guide certificate
     *# selection.
     */
    .recv = s2n_extension_recv_noop,
    .if_missing = s2n_extension_noop_if_missing,
};
