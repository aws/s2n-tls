/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <fcntl.h>

static uint32_t write_pem_file_to_stuffer_as_chain(struct s2n_stuffer *chain_out_stuffer, const char *pem_data) {
    struct s2n_stuffer chain_in_stuffer, cert_stuffer, temp_out_stuffer;
    s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, pem_data);
    s2n_stuffer_growable_alloc(&cert_stuffer, 4096);
    s2n_stuffer_growable_alloc(chain_out_stuffer, 4096);

    uint32_t chain_size = 0;
    do {
        s2n_stuffer_certificate_from_pem(&chain_in_stuffer, &cert_stuffer);

        uint32_t cert_len = s2n_stuffer_data_available(&cert_stuffer);
        uint8_t *raw_cert_data = s2n_stuffer_raw_read(&cert_stuffer, cert_len);

        if (cert_len) {
            struct s2n_blob cert_data = {.data = raw_cert_data, .size = cert_len};
            chain_size += cert_data.size + 3;
            s2n_stuffer_write_uint24(chain_out_stuffer, cert_data.size);
            s2n_stuffer_write(chain_out_stuffer, &cert_data);
        }
    } while (s2n_stuffer_data_available(&chain_in_stuffer));

    s2n_stuffer_free(&cert_stuffer);
    s2n_stuffer_free(&chain_in_stuffer);
    return chain_size;
}

struct host_verify_data {
    const char *name;
    uint8_t found_name;
    uint8_t callback_invoked;
};

static uint8_t verify_host_reject_everything(const char *host_name, size_t host_name_len, void *data) {
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 0;
}

static uint8_t verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data) {
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 1;
}


static uint8_t verify_host_verify_alt(const char *host_name, size_t host_name_len, void *data) {
    struct host_verify_data *verify_data = (struct host_verify_data *) data;

    verify_data->callback_invoked = 1;
    if (!strcmp(host_name, verify_data->name)) {
        verify_data->found_name = 1;
        return 1;
    }

    return 0;
}

int main(int argc, char **argv) {

    BEGIN_TEST();

    /* test empty trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);

        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
    }

    /* test trust store from PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN);
        EXPECT_EQUAL(0, err_code);
        EXPECT_TRUE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test trust store from non-existent PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, "dskfjasdklfjsdkl");
        EXPECT_EQUAL(S2N_ERR_T_IO, err_code);
        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test trust store from invalid PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, S2N_INVALID_HEADER_KEY);
        EXPECT_EQUAL(S2N_ERR_T_USAGE, err_code);
        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test validator in unsafe mode */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_checks(&validator);
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        long int file_size = 0;
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        EXPECT_EQUAL(S2N_ERR_T_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_NOT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        s2n_x509_validator_cleanup(&validator);
    }

    /* test validator in safe mode, but no configured trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1, NULL, NULL);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        int err_code = 0;
        err_code = s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out);
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, err_code);
        EXPECT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        s2n_x509_validator_cleanup(&validator);
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        EXPECT_EQUAL(S2N_ERR_T_OK, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1, NULL, NULL);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        EXPECT_EQUAL(S2N_ERR_T_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_NOT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        s2n_x509_validator_cleanup(&validator);
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, but the server's end-entity cert is invalid. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        EXPECT_EQUAL(S2N_ERR_T_OK, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1, NULL, NULL);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);
        //alter a random byte in the certificate to make it invalid.
        chain_data[chain_len - 5] = (uint8_t) (chain_data[chain_len - 5] + 1);
        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        int ret_val = s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out);
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, ret_val);
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_NOT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        s2n_x509_validator_cleanup(&validator);
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, but host isn't trusted*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        EXPECT_EQUAL(S2N_ERR_T_OK, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN));

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1, verify_host_reject_everything, &verify_data);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        int ret_val = s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out);
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, ret_val);
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_NOT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        s2n_x509_validator_cleanup(&validator);
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name validation succeeds */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        EXPECT_EQUAL(S2N_ERR_T_OK, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN));

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1, verify_host_accept_everything, &verify_data);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        EXPECT_EQUAL(S2N_ERR_T_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_NOT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        s2n_x509_validator_cleanup(&validator);
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name via alternative name validation succeeds
     * note: in this case, we don't have valid certs but it's enough to make sure we are properly pulling alternative names
     * from the certificate. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init(&trust_store);
        EXPECT_EQUAL(S2N_ERR_T_OK, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN));

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1, verify_host_verify_alt, &verify_data);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(
                s2n_read_test_pem(S2N_RSA_2048_SHA256_CLIENT_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_cert_public_key public_key_out;
        public_key_out.pkey.key.rsa_key.rsa = NULL;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, chain_data, chain_len, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_NOT_NULL(public_key_out.pkey.key.rsa_key.rsa);
        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_x509_validator_cleanup(&validator);
        s2n_x509_trust_store_cleanup(&trust_store);
    }

    //for OCSP, it's simpler to go through the whole handshake, so we don't have to worry about
    // emulating signatures and crypto.
    char *cert_chain;
    char *private_key;

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));
    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Test valid OCSP date range */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        s2n_config_set_check_stapled_ocsp_response(client_config, 1);
        s2n_config_set_verification_ca_file(client_config, S2N_DEFAULT_TEST_CERT_CHAIN);
        s2n_config_set_nanoseconds_since_epoch_callback(client_config, fetch_valid_ocsp_timestamp, NULL);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status,
                                                     sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client received an OCSP response. */
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (int i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Test invalid OCSP date range (after is off) */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        s2n_config_set_check_stapled_ocsp_response(client_config, 1);
        s2n_config_set_verification_ca_file(client_config, S2N_DEFAULT_TEST_CERT_CHAIN);
        s2n_config_set_nanoseconds_since_epoch_callback(client_config, fetch_expired_after_ocsp_timestamp, NULL);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status,
                                                     sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        int error_code = s2n_negotiate_test_server_and_client(server_conn, client_conn);
        EXPECT_EQUAL(-1, error_code);

        /* Verify that the client received an OCSP response. */
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (int i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        s2n_shutdown_test_server_and_client(server_conn, client_conn);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Test invalid OCSP date range (this update is off) */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        s2n_config_set_check_stapled_ocsp_response(client_config, 1);
        s2n_config_set_verification_ca_file(client_config, S2N_DEFAULT_TEST_CERT_CHAIN);
        s2n_config_set_nanoseconds_since_epoch_callback(client_config, fetch_invalid_before_ocsp_timestamp, NULL);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status,
                                                     sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        int error_code = s2n_negotiate_test_server_and_client(server_conn, client_conn);
        EXPECT_EQUAL(-1, error_code);

        /* Verify that the client received an OCSP response. */
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (int i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        s2n_shutdown_test_server_and_client(server_conn, client_conn);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Test valid OCSP date range, but the data itself is untrusted */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        s2n_config_set_check_stapled_ocsp_response(client_config, 1);
        s2n_config_set_verification_ca_file(client_config, S2N_DEFAULT_TEST_CERT_CHAIN);
        s2n_config_set_nanoseconds_since_epoch_callback(client_config, fetch_valid_ocsp_timestamp, NULL);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));

        //flip a byte that would make the signature invalid.
        uint8_t ocsp_flipped_byte = server_ocsp_status[800];
        server_ocsp_status[800] = (uint8_t) (ocsp_flipped_byte + 1);

        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status,
                                                     sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        int error_code = s2n_negotiate_test_server_and_client(server_conn, client_conn);
        //put it back so when somebody adds a test next year, they aren't wondering why their ocsp data is invalid
        server_ocsp_status[800] = ocsp_flipped_byte;
        EXPECT_EQUAL(-1, error_code);

        /* Verify that the client received an OCSP response. */
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        s2n_shutdown_test_server_and_client(server_conn, client_conn);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    END_TEST();
}
