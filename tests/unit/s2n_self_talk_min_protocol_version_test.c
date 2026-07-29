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

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    /* TLS1.2 and TLS1.3 have different version negotiation mechanisms.
     * We should test both.
     */
    for (uint8_t version = S2N_TLS12; version <= S2N_TLS13; version++) {
        /* Set up server config with TLS 1.2 as minimum version */
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(chain_and_key);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        /* Pick cipher preference with TLSv1.2 as a minimum version */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "CloudFront-TLS-1-2-2019"));

        /* Set up client config forcing TLSv1.0 */
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        if (version >= S2N_TLS13) {
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));
        } else {
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls12"));
        }

        /* Set up server connection */
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        /* Set up client connection forcing TLSv1.0 */
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        /* Force TLSv1.0 on client so that server will fail handshake */
        client_conn->client_protocol_version = S2N_TLS10;

        /* Use in-memory IO stuffer pair */
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        /* Negotiate the handshake — expect failure due to unsupported version */
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

        /* Check that blinding was not invoked */
        EXPECT_EQUAL(s2n_connection_get_delay(server_conn), 0);
    }

    END_TEST();
}
