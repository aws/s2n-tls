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

#define SUPPORTED_CERTIFICATE_FORMATS (2)

static const char *certificate_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS8_CERT_CHAIN };
static const char *private_key_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_KEY, S2N_RSA_2048_PKCS8_KEY };

static uint64_t s2n_test_mock_time = 0;

static int s2n_test_mock_clock(void *in, uint64_t *out)
{
    *out = s2n_test_mock_time;
    return 0;
}

int main(int argc, char **argv)
{
    s2n_blocked_status blocked;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    for (int is_dh_key_exchange = 0; is_dh_key_exchange <= 1; is_dh_key_exchange++) {
        struct s2n_cert_chain_and_key *chain_and_keys[SUPPORTED_CERTIFICATE_FORMATS];

        char *cert_chain_pem = NULL;
        char *private_key_pem = NULL;
        char *dhparams_pem = NULL;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        /* Set up server config */
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_OK(s2n_config_set_tls12_security_policy(server_config));
        EXPECT_SUCCESS(s2n_config_set_monotonic_clock(server_config, s2n_test_mock_clock, NULL));
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_read_test_pem(certificate_paths[cert], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(private_key_paths[cert], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_NOT_NULL(chain_and_keys[cert] = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_keys[cert], cert_chain_pem, private_key_pem));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_keys[cert]));
        }

        if (is_dh_key_exchange) {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
        }

        /* Set up client config */
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_OK(s2n_config_set_tls12_security_policy(client_config));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_monotonic_clock(client_config, s2n_test_mock_clock, NULL));

        /* Set up server connection */
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Set up client connection */
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* Use in-memory IO stuffer pair */
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        /* Negotiate the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);

        /* Release handshake buffers on client */
        EXPECT_SUCCESS(s2n_connection_free_handshake(client_conn));

        /* Client sends data in increasing chunks, server reads and verifies.
         * With dynamic record threshold enabled, the first 0x7fff bytes use
         * small TLS records (fitting in one TCP segment) for lower latency.
         */
        char send_buffer[0xffff];
        char recv_buffer[0xffff];

        uint16_t timeout = 1;
        EXPECT_SUCCESS(s2n_connection_set_dynamic_record_threshold(client_conn, 0x7fff, timeout));

        int i = 0;
        for (i = 1; i < 0xffff - 100; i += 100) {
            for (int j = 0; j < i; j++) {
                send_buffer[j] = 33;
            }
            EXPECT_EQUAL(s2n_send(client_conn, send_buffer, i, &blocked), i);

            /* Server reads the data */
            char *ptr = recv_buffer;
            int size = i;
            do {
                int bytes_read = 0;
                EXPECT_SUCCESS(bytes_read = s2n_recv(server_conn, ptr, size, &blocked));
                size -= bytes_read;
                ptr += bytes_read;
            } while (size);

            for (int j = 0; j < i; j++) {
                EXPECT_EQUAL(recv_buffer[j], 33);
            }

            /* Reset the IO stuffer cursors after all data is consumed,
             * preventing unbounded growth that causes expensive reallocs.
             */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), 0);
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&io_pair.server_in));
        }

        /* Release the buffers to validate we can continue IO after */
        EXPECT_SUCCESS(s2n_connection_release_buffers(server_conn));

        /* Fill the buffer for the final send */
        for (int j = 0; j < i; j++) {
            send_buffer[j] = 33;
        }

        /* Release buffers on client to validate we can continue IO after */
        EXPECT_SUCCESS(s2n_connection_release_buffers(client_conn));

        /* Simulate timeout for dynamic record threshold by advancing mock clock.
         * After the timeout period, active_application_bytes_consumed is reset
         * to 0 before writing data, so its value should equal bytes written
         * after the send.
         */
        s2n_test_mock_time += (uint64_t) timeout * 1000000000 + 1;

        ssize_t bytes_written = s2n_send(client_conn, send_buffer, i, &blocked);
        EXPECT_TRUE(bytes_written > 0);
        EXPECT_EQUAL((uint64_t) bytes_written, client_conn->active_application_bytes_consumed);

        /* Server reads the final chunk */
        {
            char *ptr = recv_buffer;
            int size = i;
            do {
                int bytes_read = 0;
                EXPECT_SUCCESS(bytes_read = s2n_recv(server_conn, ptr, size, &blocked));
                size -= bytes_read;
                ptr += bytes_read;
            } while (size);
        }

        /* Graceful shutdown (both sides) */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        /* Clean up cert chains */
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_keys[cert]));
        }

        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);
    }

    END_TEST();
}
