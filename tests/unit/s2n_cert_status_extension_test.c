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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_cert_status.h"

const uint8_t ocsp_data[] = "OCSP DATA";

int s2n_test_enable_sending_extension(struct s2n_connection *conn, struct s2n_cert_chain_and_key *chain_and_key)
{
    conn->status_type = S2N_STATUS_REQUEST_OCSP;
    conn->handshake_params.our_chain_and_key = chain_and_key;
    EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(chain_and_key, ocsp_data, s2n_array_len(ocsp_data)));
    conn->x509_validator.state = VALIDATED;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* should_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Don't send by default */
        EXPECT_FALSE(s2n_cert_status_extension.should_send(conn));

        /* Send if all prerequisites met */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        EXPECT_TRUE(s2n_cert_status_extension.should_send(conn));

        /* Send if client */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        conn->mode = S2N_CLIENT;
        EXPECT_TRUE(s2n_cert_status_extension.should_send(conn));

        /* Send if server */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        conn->mode = S2N_SERVER;
        EXPECT_TRUE(s2n_cert_status_extension.should_send(conn));

        /* Don't send if no certificate set */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        conn->handshake_params.our_chain_and_key = NULL;
        EXPECT_FALSE(s2n_cert_status_extension.should_send(conn));

        /* Don't send if no ocsp data */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        EXPECT_SUCCESS(s2n_free(&conn->handshake_params.our_chain_and_key->ocsp_status));
        EXPECT_FALSE(s2n_cert_status_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_cert_status_extension.send(conn, &stuffer));

        uint8_t request_type;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &request_type));
        EXPECT_EQUAL(request_type, S2N_STATUS_REQUEST_OCSP);

        uint32_t ocsp_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint24(&stuffer, &ocsp_size));
        EXPECT_EQUAL(ocsp_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(ocsp_size, s2n_array_len(ocsp_data));

        uint8_t *actual_ocsp_data;
        EXPECT_NOT_NULL(actual_ocsp_data = s2n_stuffer_raw_read(&stuffer, ocsp_size));
        EXPECT_BYTEARRAY_EQUAL(actual_ocsp_data, ocsp_data, ocsp_size);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_cert_status_extension.send(conn, &stuffer));

        EXPECT_EQUAL(conn->status_response.size, 0);
        EXPECT_SUCCESS(s2n_cert_status_extension.recv(conn, &stuffer));
        EXPECT_BYTEARRAY_EQUAL(conn->status_response.data, ocsp_data, s2n_array_len(ocsp_data));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test recv - not ocsp */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, S2N_STATUS_REQUEST_NONE));

        EXPECT_EQUAL(conn->status_response.size, 0);
        EXPECT_SUCCESS(s2n_cert_status_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->status_response.size, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test recv - bad ocsp data */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));

        DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_cert_status_extension.send(conn, &stuffer));

        if (s2n_x509_ocsp_stapling_supported()) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_status_extension.recv(conn, &stuffer),
                    S2N_ERR_INVALID_OCSP_RESPONSE);
        } else {
            /* s2n_x509_validator_validate_cert_stapled_ocsp_response returns untrusted error if ocsp is not supported */
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_status_extension.recv(conn, &stuffer),
                    S2N_ERR_CERT_UNTRUSTED);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Self-talk tests */
    if (s2n_x509_ocsp_stapling_supported() && s2n_is_tls13_fully_supported()) {
        uint8_t ocsp_response[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t ocsp_response_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_OCSP_RESPONSE_DER, ocsp_response, &ocsp_response_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_TRUE(ocsp_response_len > 0);

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *ocsp_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ocsp_chain_and_key, S2N_OCSP_SERVER_CERT, S2N_OCSP_SERVER_KEY));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(ocsp_chain_and_key, ocsp_response, ocsp_response_len));

        /* Client requests OCSP staple, and server sends OCSP response */
        {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_OCSP_CA_CERT, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ocsp_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2n Test Cert"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

            uint32_t client_received_ocsp_response_len = 0;
            const uint8_t *client_received_ocsp_response = s2n_connection_get_ocsp_response(client_conn,
                    &client_received_ocsp_response_len);
            EXPECT_NOT_NULL(client_received_ocsp_response);

            uint32_t server_received_ocsp_response_len = 0;
            const uint8_t *server_received_ocsp_response = s2n_connection_get_ocsp_response(server_conn,
                    &server_received_ocsp_response_len);
            /* Only the client requested a response, the server should not have received one. */
            EXPECT_NULL(server_received_ocsp_response);

            /* The server sent an OCSP response, and the client received an OCSP response */
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 1);
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 1);
        }

        /* Server requests OCSP staple, and client sends OCSP response */
        {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_OCSP_CA_CERT, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_NONE));

            EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, ocsp_chain_and_key));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ocsp_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(server_config, S2N_STATUS_REQUEST_OCSP));

            EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_OCSP_CA_CERT, NULL));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2n Test Cert"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

            uint32_t client_received_ocsp_response_len = 0;
            const uint8_t *client_received_ocsp_response = s2n_connection_get_ocsp_response(client_conn,
                    &client_received_ocsp_response_len);
            /* Only the server requested a response, the client should not have received one. */
            EXPECT_NULL(client_received_ocsp_response);

            uint32_t server_received_ocsp_response_len = 0;
            const uint8_t *server_received_ocsp_response = s2n_connection_get_ocsp_response(server_conn,
                    &server_received_ocsp_response_len);
            EXPECT_NOT_NULL(server_received_ocsp_response);

            /* The server did not send an OCSP response, and the client did not receive an OCSP response */
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 0);
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 0);
        }

        /* Client and server both request OCSP staples, and client and server both send responses */
        {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_OCSP_CA_CERT, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));

            EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, ocsp_chain_and_key));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ocsp_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(server_config, S2N_STATUS_REQUEST_OCSP));

            EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_OCSP_CA_CERT, NULL));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2n Test Cert"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

            uint32_t client_received_ocsp_response_len = 0;
            const uint8_t *client_received_ocsp_response = s2n_connection_get_ocsp_response(client_conn,
                    &client_received_ocsp_response_len);
            EXPECT_NOT_NULL(client_received_ocsp_response);

            uint32_t server_received_ocsp_response_len = 0;
            const uint8_t *server_received_ocsp_response = s2n_connection_get_ocsp_response(server_conn,
                    &server_received_ocsp_response_len);
            EXPECT_NOT_NULL(server_received_ocsp_response);

            /* The server sent an OCSP response, and the client received an OCSP response */
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 1);
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 1);
        }

        /* Server sets an OCSP response but client does not request OCSP stapling */
        {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_OCSP_CA_CERT, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_NONE));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ocsp_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2n Test Cert"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

            uint32_t client_received_ocsp_response_len = 0;
            const uint8_t *client_received_ocsp_response = s2n_connection_get_ocsp_response(client_conn,
                    &client_received_ocsp_response_len);

            uint32_t server_received_ocsp_response_len = 0;
            const uint8_t *server_received_ocsp_response = s2n_connection_get_ocsp_response(server_conn,
                    &server_received_ocsp_response_len);

            /* Both the server and client did not request OCSP responses, so neither should have received them. */
            EXPECT_NULL(client_received_ocsp_response);
            EXPECT_NULL(server_received_ocsp_response);

            /* The server did not send an OCSP response, and the client did not receive an OCSP response */
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 0);
            EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 0);
        }
    }

    END_TEST();
    return 0;
}
