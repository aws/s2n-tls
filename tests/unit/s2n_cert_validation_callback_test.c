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
#include "tls/s2n_x509_validator.h"

struct s2n_cert_validation_data {
    unsigned call_accept_or_reject : 1;
    unsigned accept : 1;
    unsigned return_success : 1;

    int invoked_count;
};

static int s2n_test_cert_validation_callback(struct s2n_connection *conn, struct s2n_cert_validation_info *info, void *ctx)
{
    struct s2n_cert_validation_data *data = (struct s2n_cert_validation_data *) ctx;

    data->invoked_count += 1;

    int ret = S2N_FAILURE;
    if (data->return_success) {
        ret = S2N_SUCCESS;
    }

    if (!data->call_accept_or_reject) {
        return ret;
    }

    if (data->accept) {
        EXPECT_SUCCESS(s2n_cert_validation_accept(info));
    } else {
        EXPECT_SUCCESS(s2n_cert_validation_reject(info));
    }

    return ret;
}

static int s2n_test_cert_validation_callback_self_talk(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *ctx)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *peer_cert_chain = s2n_cert_chain_and_key_new(),
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_NOT_NULL(peer_cert_chain);

    /* Ensure that the peer's certificate chain can be retrieved at the time the callback is invoked */
    EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(conn, peer_cert_chain));
    uint32_t peer_cert_chain_len = 0;
    EXPECT_SUCCESS(s2n_cert_chain_get_length(peer_cert_chain, &peer_cert_chain_len));
    EXPECT_TRUE(peer_cert_chain_len > 0);

    return s2n_test_cert_validation_callback(conn, info, ctx);
}

static int s2n_test_cert_validation_callback_self_talk_server(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *ctx)
{
    /* Ensure that the callback was invoked on the server connection */
    EXPECT_EQUAL(conn->mode, S2N_SERVER);

    /* Ensure that the client's certificate chain can be retrieved at the time the callback was invoked */
    uint8_t *der_cert_chain = 0;
    uint32_t cert_chain_len = 0;
    EXPECT_SUCCESS(s2n_connection_get_client_cert_chain(conn, &der_cert_chain, &cert_chain_len));
    EXPECT_TRUE(cert_chain_len > 0);

    return s2n_test_cert_validation_callback_self_talk(conn, info, ctx);
}

static int s2n_test_cert_validation_callback_self_talk_ocsp(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *ctx)
{
    /* Ensure that the OCSP response was received prior to invoking the callback */
    uint32_t ocsp_response_length = 0;
    const uint8_t *ocsp_response = s2n_connection_get_ocsp_response(conn, &ocsp_response_length);
    EXPECT_NOT_NULL(ocsp_response);
    EXPECT_TRUE(ocsp_response_length > 0);

    return s2n_test_cert_validation_callback_self_talk(conn, info, ctx);
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Accept/reject tests */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_validation_accept(NULL), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_validation_reject(NULL), S2N_ERR_NULL);

        /* Accept sets the proper state */
        {
            struct s2n_cert_validation_info info = { 0 };

            EXPECT_SUCCESS(s2n_cert_validation_accept(&info));

            EXPECT_EQUAL(info.finished, true);
            EXPECT_EQUAL(info.accepted, true);
        }

        /* Reject sets the proper state */
        {
            struct s2n_cert_validation_info info = { 0 };

            EXPECT_SUCCESS(s2n_cert_validation_reject(&info));

            EXPECT_EQUAL(info.finished, true);
            EXPECT_EQUAL(info.accepted, false);
        }

        /* Calls to accept/reject fail if accept has already been called */
        {
            struct s2n_cert_validation_info info = { 0 };

            EXPECT_SUCCESS(s2n_cert_validation_accept(&info));

            for (int i = 0; i < 10; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_validation_accept(&info), S2N_ERR_INVALID_STATE);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_validation_reject(&info), S2N_ERR_INVALID_STATE);
            }

            /* State was updated from the successful call */
            EXPECT_EQUAL(info.finished, true);
            EXPECT_EQUAL(info.accepted, true);
        }

        /* Calls to accept/reject fail if reject has already been called */
        {
            struct s2n_cert_validation_info info = { 0 };

            EXPECT_SUCCESS(s2n_cert_validation_reject(&info));

            for (int i = 0; i < 10; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_validation_reject(&info), S2N_ERR_INVALID_STATE);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_validation_accept(&info), S2N_ERR_INVALID_STATE);
            }

            /* State was updated from the successful call */
            EXPECT_EQUAL(info.finished, true);
            EXPECT_EQUAL(info.accepted, false);
        }
    }

    /* Test s2n_cert_validation_callback */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        /* clang-format off */
        struct {
            const struct s2n_cert_validation_data data;
            s2n_error expected_error;
        } test_cases[] = {
            /* No error when accept is called from the callback */
            {
                .data = { .call_accept_or_reject = true, .accept = true, .return_success = true },
                .expected_error = S2N_ERR_OK
            },

            /* Error if reject was called from the callback */
            {
                .data = { .call_accept_or_reject = true, .accept = false, .return_success = true },
                .expected_error = S2N_ERR_CERT_REJECTED
            },

            /* Error if the callback doesn't return successfully */
            {
                .data = { .call_accept_or_reject = true, .accept = true, .return_success = false },
                .expected_error = S2N_ERR_CANCELLED
            },
            {
                .data = { .call_accept_or_reject = true, .accept = false, .return_success = false },
                .expected_error = S2N_ERR_CANCELLED
            },
            {
                .data = { .call_accept_or_reject = false, .return_success = false },
                .expected_error = S2N_ERR_CANCELLED
            },

            /* Error if accept or reject wasn't called from the callback */
            {
                .data = { .call_accept_or_reject = false, .return_success = true },
                .expected_error = S2N_ERR_INVALID_STATE
            },
        };
        /* clang-format on */

        /* s2n_x509_validator test */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
            s2n_x509_trust_store_init_empty(&trust_store);

            char cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, cert_chain));

            DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            struct s2n_cert_validation_data data = test_cases[i].data;
            EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, s2n_test_cert_validation_callback, &data));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_set_server_name(conn, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, conn, chain_data, chain_len,
                        &pkey_type, &public_key_out));
            } else {
                EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, conn, chain_data,
                                                chain_len, &pkey_type, &public_key_out),
                        expected_error);
            }

            EXPECT_EQUAL(data.invoked_count, 1);
        }

        /* The callback is invoked even if cert verification is disabled */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
            s2n_x509_trust_store_init_empty(&trust_store);

            char cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, cert_chain));

            /* Initialize the x509_validator with skip_cert_validation enabled */
            DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            struct s2n_cert_validation_data data = test_cases[i].data;
            EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, s2n_test_cert_validation_callback, &data));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, conn, chain_data, chain_len,
                        &pkey_type, &public_key_out));
            } else {
                EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, conn, chain_data,
                                                chain_len, &pkey_type, &public_key_out),
                        expected_error);
            }

            EXPECT_EQUAL(data.invoked_count, 1);
        }

        /* Self-talk: callback is invoked on the client after receiving the server's certificate */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            struct s2n_cert_validation_data data = test_cases[i].data;
            EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, s2n_test_cert_validation_callback_self_talk, &data));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        expected_error);
            }

            EXPECT_EQUAL(data.invoked_count, 1);
        }

        /* Self-talk: callback is invoked on the server after receiving the client's certificate */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

            struct s2n_cert_validation_data data = test_cases[i].data;
            EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(server_config,
                    s2n_test_cert_validation_callback_self_talk_server, &data));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        expected_error);
            }

            EXPECT_EQUAL(data.invoked_count, 1);
        }

        /* Self-talk: callback is invoked after an OCSP response is received in TLS 1.3
         *
         * Currently, the cert validation callback is invoked after validating the certificate
         * chain and after processing the Certificate message extensions. In TLS 1.3, the OCSP
         * response is sent in a Certificate message extension, and should be accessible to the
         * cert validation callback.
         *
         * In TLS 1.2, the OCSP response is sent in a separate CertificateStatus message which is
         * received after the cert validation callback is invoked. So, OCSP information won't be
         * accessible from the callback in TLS 1.2.
         */
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            if (!s2n_x509_ocsp_stapling_supported() || !s2n_is_tls13_fully_supported()) {
                break;
            }

            uint8_t ocsp_response[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t ocsp_response_len = 0;
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_OCSP_RESPONSE_DER, ocsp_response, &ocsp_response_len,
                    S2N_MAX_TEST_PEM_SIZE));
            EXPECT_TRUE(ocsp_response_len > 0);

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *ocsp_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ocsp_chain_and_key,
                    S2N_OCSP_SERVER_CERT, S2N_OCSP_SERVER_KEY));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(ocsp_chain_and_key, ocsp_response, ocsp_response_len));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ocsp_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_OCSP_CA_CERT, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));

            struct s2n_cert_validation_data data = test_cases[i].data;
            EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(client_config,
                    s2n_test_cert_validation_callback_self_talk_ocsp, &data));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "s2n Test Cert"));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_error expected_error = test_cases[i].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        expected_error);
            }

            EXPECT_EQUAL(data.invoked_count, 1);
        }
    }

    END_TEST();
}
