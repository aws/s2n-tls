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

static const uint8_t buf_to_send[1023] = { 27 };

/**
 * This test ensures that we don't allow releasing connection buffers if they contain part
 * of the unprocessed record, avoiding connection corruption.
 */
int main(int argc, char **argv)
{
    s2n_blocked_status blocked;
    uint8_t buf[sizeof(buf_to_send)];

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_OK(s2n_config_set_tls12_security_policy(server_config));
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
            s2n_cert_chain_and_key_ptr_free);
    char *cert_chain_pem = NULL;
    char *private_key_pem = NULL;
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_OK(s2n_config_set_tls12_security_policy(client_config));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

    /* Use a stuffer pair for the client-server I/O, but set up the server
     * with a separate intermediate stuffer so we can control how much data
     * it sees at a time (to simulate partial record delivery).
     */
    DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
    EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));

    /* Client uses the stuffer pair normally */
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_pair.client_in, &io_pair.server_in, client_conn));

    /* Server uses a separate "in" stuffer so we can manually control how
     * much data is available for reading. Server still writes directly to
     * client_in so the client can read responses.
     */
    DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &io_pair.client_in, server_conn));

    /* Negotiate the handshake by shuttling data between io_pair.server_in
     * and server_in manually, similar to how the original test shuttled
     * data between a pipe and a stuffer.
     */
    {
        bool server_done = false, client_done = false;

        do {
            if (!client_done) {
                int ret = s2n_negotiate(client_conn, &blocked);
                EXPECT_TRUE(ret == 0 || s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED);
                if (ret == 0) {
                    client_done = true;
                }
            }

            /* Move data from io_pair.server_in to the server's actual input stuffer */
            uint32_t available = s2n_stuffer_data_available(&io_pair.server_in);
            if (available > 0) {
                EXPECT_SUCCESS(s2n_stuffer_copy(&io_pair.server_in, &server_in, available));
            }

            if (!server_done) {
                int ret = s2n_negotiate(server_conn, &blocked);
                EXPECT_TRUE(ret == 0 || s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED);
                if (ret == 0) {
                    server_done = true;
                }
            }
        } while (!client_done || !server_done);
    }

    /* Client sends data. The encrypted record lands in io_pair.server_in. */
    EXPECT_EQUAL(s2n_send(client_conn, buf_to_send, sizeof(buf_to_send), &blocked), sizeof(buf_to_send));

    /* Copy only 100 bytes of the record into the server's input stuffer,
     * simulating partial record delivery.
     */
    uint32_t total_available = s2n_stuffer_data_available(&io_pair.server_in);
    EXPECT_TRUE(total_available > 100);
    EXPECT_SUCCESS(s2n_stuffer_copy(&io_pair.server_in, &server_in, 100));

    /* s2n_recv should fail as we received only part of the record */
    EXPECT_FAILURE(s2n_recv(server_conn, buf, sizeof(buf), &blocked));
    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

    /* Now try to release the buffers and expect failure as buffers are not empty */
    EXPECT_FAILURE(s2n_connection_release_buffers(server_conn));

    /* Copy the rest of the record into the server's input stuffer */
    uint32_t remaining = s2n_stuffer_data_available(&io_pair.server_in);
    EXPECT_SUCCESS(s2n_stuffer_copy(&io_pair.server_in, &server_in, remaining));

    /* s2n_recv should now succeed with the full record available */
    ssize_t ret = s2n_recv(server_conn, buf, sizeof(buf), &blocked);
    EXPECT_EQUAL(ret, sizeof(buf_to_send));
    EXPECT_BYTEARRAY_EQUAL(buf, buf_to_send, ret);

    /* Since full record was processed, we should be able to release buffers */
    EXPECT_SUCCESS(s2n_connection_release_buffers(server_conn));

    /* Reconnect the server to read directly from the stuffer pair for shutdown,
     * since the intermediate stuffer was only needed for partial-record testing.
     */
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_pair.server_in, &io_pair.client_in, server_conn));

    /* Shutdown */
    EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    /* Clean up */
    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();

    return 0;
}
