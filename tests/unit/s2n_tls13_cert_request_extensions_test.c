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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_server_signature_algorithms.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test correct required extension (sig_alg) sent and received */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        conn->actual_protocol_version = S2N_TLS13;

        EXPECT_EQUAL(conn->handshake_params.server_sig_hash_algs.len, 0);
        EXPECT_SUCCESS(s2n_tls13_cert_req_send(conn));
        EXPECT_SUCCESS(s2n_tls13_cert_req_recv(conn));
        EXPECT_NOT_EQUAL(conn->handshake_params.server_sig_hash_algs.len, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test client fails to parse certificate request with no extensions */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Write 0 length request context https://tools.ietf.org/html/rfc8446#section-4.3.2 */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_MISSING_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    END_TEST();

    return 0;
}
