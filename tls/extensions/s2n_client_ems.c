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

#include <sys/param.h>
#include <stdint.h>

#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_ems.h"

#include "utils/s2n_safety.h"

static int s2n_client_ems_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_ems_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);
static bool s2n_client_ems_should_send(struct s2n_connection *conn);

const s2n_extension_type s2n_client_ems_extension = {
    .iana_value = TLS_EXTENSION_EMS,
    .is_response = false,
    .send = s2n_client_ems_send,
    .recv = s2n_client_ems_recv,
    .should_send = s2n_client_ems_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static int s2n_client_ems_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);

    /** Write nothing. The extension just needs to exist.
     *
     *= https://tools.ietf.org/rfc/rfc7627#section-5.1
     *# 
     *#   This document defines a new TLS extension, "extended_master_secret"
     *#   (with extension type 0x0017), which is used to signal both client and
     *#   server to use the extended master secret computation.  The
     *#   "extension_data" field of this extension is empty.  Thus, the entire
     *#   encoding of the extension is 00 17 00 00 (in hexadecimal.)
     **/

    return S2N_SUCCESS;
}

static int s2n_client_ems_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    POSIX_ENSURE_REF(conn);

    /* Read nothing. The extension just needs to exist. */
    conn->ems_negotiated = true;

    return S2N_SUCCESS;
}

static bool s2n_client_ems_should_send(struct s2n_connection *conn)
{
    /* TODO: https://github.com/aws/s2n-tls/issues/2990 
     * We gate on the unit tests because the feature
     * isn't complete and will mess up our integ tests. */
    return conn && s2n_in_unit_test();
}
