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

static int fetch_expired_after_ocsp_timestamp(void *data, uint64_t *timestamp) {
    *timestamp = 7283958536000000000;
    return 0;
}

#if S2N_OCSP_STAPLING_SUPPORTED
static int fetch_invalid_before_ocsp_timestamp(void *data, uint64_t *timestamp) {
    *timestamp = 1425019604000000000;
    return 0;
}

static int fetch_not_expired_ocsp_timestamp(void *data, uint64_t *timestamp) {
    *timestamp = 1552824239000000000;
    return 0;
}
#endif /* S2N_OCSP_STAPLING_SUPPORTED */

static int read_file(struct s2n_stuffer *file_output, const char *path, uint32_t max_len) {
    FILE *fd = fopen(path, "rb");
    s2n_stuffer_alloc(file_output, max_len);

    if(fd) {
        char data[1024];
        size_t r = 0;
        while((r =fread(data, 1, sizeof(data), fd)) > 0) {
            s2n_stuffer_write_bytes(file_output, (const uint8_t *)data, (const uint32_t)r);
        }
        fclose(fd);
        return s2n_stuffer_data_available(file_output) > 0;
    }

    return -1;
}

static uint32_t write_pem_file_to_stuffer_as_chain(struct s2n_stuffer *chain_out_stuffer, const char *pem_data, uint8_t protocol_version) {
    struct s2n_stuffer chain_in_stuffer = {0}, cert_stuffer = {0};
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
            /* Add an extra uint8_t to represent 0 length certificate extensions in tls13 */
            if (protocol_version >= S2N_TLS13) {
                s2n_stuffer_write_uint16(chain_out_stuffer, 0);
                chain_size += 2;
            }
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
    EXPECT_SUCCESS(s2n_disable_tls13());

    /* test empty trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
    }

    /* test trust store from PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL);
        EXPECT_EQUAL(0, err_code);
        EXPECT_TRUE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test trust store from PEM */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        char *cert_chain = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        int err_code = s2n_x509_trust_store_add_pem(&trust_store, cert_chain);
        free(cert_chain);
        EXPECT_EQUAL(0, err_code);
        EXPECT_TRUE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test trust store from non-existent PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, "dskfjasdklfjsdkl", NULL);
        EXPECT_EQUAL(-1, err_code);
        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test trust store from invalid PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, S2N_INVALID_HEADER_KEY, NULL);
        EXPECT_EQUAL(-1, err_code);
        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in unsafe mode */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    }

    /* test validator in unsafe mode, make sure max depth is honored on the read, but not an error condition */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        EXPECT_SUCCESS(s2n_x509_validator_set_max_chain_depth(&validator, 2));
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    }

    /* test validator in safe mode, but no configured trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        EXPECT_FAILURE_WITH_ERRNO(s2n_x509_validator_set_max_chain_depth(&validator, 0), S2N_ERR_INVALID_ARGUMENT);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, but no configured trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);

        EXPECT_NOT_NULL(connection);
        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        int err_code = s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                                              &pkey_type, &public_key_out);
        EXPECT_EQUAL(0, verify_data.callback_invoked);
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, err_code);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store and test that SAN URI callback is invoked. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_URI_SANS_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = "foo://bar" };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_URI_SANS_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 1);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, using s2n PEM Parser. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        char *cert_chain = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        int err_code = s2n_x509_trust_store_add_pem(&trust_store, cert_chain);
        free(cert_chain);
        EXPECT_EQUAL(0, err_code);

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, but max chain depth is exceeded*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        EXPECT_SUCCESS(s2n_x509_validator_set_max_chain_depth(&validator, 2));
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_FAILURE_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out),
                        S2N_ERR_CERT_UNTRUSTED);
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(0, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test expired certificate fails as untrusted*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_expired_after_ocsp_timestamp, NULL);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_config_set_wall_clock(connection->config, old_clock, NULL);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, but the server's end-entity cert is invalid. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);
        /* alter a random byte in the certificate to make it invalid */
        chain_data[500] = (uint8_t) (chain_data[500] << 2);
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        int ret_val = s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out);
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, ret_val);
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, but host isn't trusted*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_reject_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        int ret_val = s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out);
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, ret_val);
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store, but host isn't trusted, using s2n PEM Parser */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        char *cert_chain = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        int err_code = s2n_x509_trust_store_add_pem(&trust_store, cert_chain);
        free(cert_chain);
        EXPECT_EQUAL(0, err_code);

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_reject_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        int ret_val = s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out);
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, ret_val);
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_connection_free(connection);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name validation succeeds */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name validation succeeds, using s2n PEM Parser */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        char *cert_chain = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        int err_code = s2n_x509_trust_store_add_pem(&trust_store, cert_chain);
        free(cert_chain);
        EXPECT_EQUAL(0, err_code);

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_pkey_free(&public_key_out);

        s2n_connection_free(connection);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name via alternative name validation succeeds
     * note: in this case, we don't have valid certs but it's enough to make sure we are properly pulling alternative names
     * from the certificate. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct host_verify_data verify_data = {.name = "127.0.0.1", .found_name = 0, .callback_invoked = 0,};
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(
                s2n_read_test_pem(S2N_RSA_2048_SHA256_CLIENT_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name via alternative name validation fails, and
     * no Common Name validation happens as DNS alternative name is present. note: in this case, we don't have valid certs but
     * it's enough to make sure we are properly validating alternative names and common name.*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        /* Name matches CN on certificate (CN=localhost), but no match in alternative names */
        struct host_verify_data verify_data = {.name = "localhost", .found_name = 0, .callback_invoked = 0,};
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(
                s2n_read_test_pem(S2N_RSA_2048_SHA256_CLIENT_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(0, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with properly configured trust store. host name via common name validation succeeds,
     * non-dns alternative names are ignored. note: in this case, we don't have valid certs but it's enough to make sure
     * we are properly validating alternative names and common name.*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        /* Name matches CN on certificate (CN=localhost) */
        struct host_verify_data verify_data = {.name = "localhost", .found_name = 0, .callback_invoked = 0,};
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(
                s2n_read_test_pem(S2N_RSA_2048_SHA256_NO_DNS_SANS_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }
#if S2N_OCSP_STAPLING_SUPPORTED
    /* Test valid OCSP date range */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_EQUAL(S2N_CERT_OK, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                          s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len),
                                                                                          ocsp_data_len));
        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test valid OCSP date range without nextUpdate field */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_NO_NEXT_UPDATE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_not_expired_ocsp_timestamp, NULL);

        EXPECT_EQUAL(S2N_CERT_OK, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                          s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len),
                                                                                          ocsp_data_len));
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_config_set_wall_clock(connection->config, old_clock, NULL);

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test valid OCSP date range, but with s2n PEM Parser */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

         char *cert_chain = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_CA_CERT, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        int err_code = s2n_x509_trust_store_add_pem(&trust_store, cert_chain);
        free(cert_chain);
        EXPECT_EQUAL(0, err_code);

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        s2n_pkey_free(&public_key_out);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_EQUAL(S2N_CERT_OK, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                          s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len),
                                                                                          ocsp_data_len));
        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test invalid OCSP date range (after is off) */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_expired_after_ocsp_timestamp, NULL);

        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_EQUAL(S2N_CERT_ERR_EXPIRED, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                          s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len),
                                                                                          ocsp_data_len));
        s2n_config_set_wall_clock(connection->config, old_clock, NULL);
        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test invalid OCSP date range (thisupdate is off) */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_invalid_before_ocsp_timestamp, NULL);

        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_EQUAL(S2N_CERT_ERR_EXPIRED, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                                  s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len),
                                                                                                  ocsp_data_len));

        s2n_config_set_wall_clock(connection->config, old_clock, NULL);

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test valid OCSP date range, but the data itself is untrusted */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        /* flip a byte right in the middle of the cert */
        uint8_t *raw_data = (uint8_t *)s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);
        raw_data[800] = (uint8_t) (raw_data[800] + 1);

        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                                  raw_data,
                                                                                                  ocsp_data_len));

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test valid OCSP date range and data, but the stapled response was signed with an issuer not in the chain of trust */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_WILDCARD_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_WILDCARD_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        uint8_t *raw_data = (uint8_t *)s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);

        EXPECT_EQUAL(S2N_CERT_ERR_INVALID, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                                  raw_data,
                                                                                                  ocsp_data_len));

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test OCSP response signed by the correct responder certificate, but not for the requested certificate.
     * (So this would be a completely valid response to a different OCSP request for the other certificate.)  */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_ECDSA_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        uint8_t *raw_data = (uint8_t *)s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);

        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                                  raw_data,
                                                                                                  ocsp_data_len));

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test OCSP response signed by the wrong responder certificate, but the requested certificate was signed.
     * (however this incorrect OCSP responder certificate is a valid OCSP responder for some other case and chains
     * to a trusted root). Thus, this response is not valid for any request.  */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_ECDSA_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_WRONG_SIGNER_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        uint8_t *raw_data = (uint8_t *)s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);

        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                                    raw_data,
                                                                                                    ocsp_data_len));

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test OCSP response status is revoked */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer;
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_REVOKED_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_EQUAL(S2N_CERT_ERR_REVOKED, s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                                                         s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len),
                                                                                         ocsp_data_len));
        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }
#endif /* S2N_OCSP_STAPLING_SUPPORTED */
    /* test validator in safe mode, with default host name validator. Connection server name matches alternative name on a certificate. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_WILDCARD_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_WILDCARD_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with default host name validator. Connection server name matches wildcard alternative name on a certificate. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_WILDCARD_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        EXPECT_SUCCESS(s2n_set_server_name(connection, "test.localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_WILDCARD_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with default host name validator. Connection server does not match alternative names on a certificate. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_WILDCARD_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        EXPECT_SUCCESS(s2n_set_server_name(connection, "127.0.0.1"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_WILDCARD_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* test validator in safe mode, with default host name validator. No connection server name supplied. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_WILDCARD_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_WILDCARD_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test trust store in a configuration can handle invalid PEM without crashing */
    {
        struct s2n_config *cfg = s2n_config_new();
        s2n_config_add_pem_to_trust_store(cfg, "");
        s2n_config_free(cfg);
        /* Expect no crash. */
    }

    /* Test one trailing byte in cert validator */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct s2n_stuffer chain_stuffer;
        EXPECT_SUCCESS(read_file(&chain_stuffer, S2N_ONE_TRAILING_BYTE_CERT_BIN, S2N_MAX_TEST_PEM_SIZE));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    }

    /* Test more trailing bytes in cert validator for negative case */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct s2n_stuffer chain_stuffer;
        EXPECT_SUCCESS(read_file(&chain_stuffer, S2N_FOUR_TRAILING_BYTE_CERT_BIN, S2N_MAX_TEST_PEM_SIZE));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;

        /* Expect to return S2N_CERT_ERR_UNTRUSTED */
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    }

    /* Test validator trusts a SHA-1 signature in a certificate chain if certificate validation is off */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_PKCS1_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));

        EXPECT_NOT_NULL(connection);
        connection->actual_protocol_version = S2N_TLS13;

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));
        
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS13);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        validator.skip_cert_validation = 1;
        EXPECT_EQUAL(S2N_CERT_OK,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        s2n_stuffer_free(&chain_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_config_free(config);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test validator does not trust a SHA-1 signature in a certificate chain */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_PKCS1_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));

        EXPECT_NOT_NULL(connection);
        connection->actual_protocol_version = S2N_TLS13;

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));
        
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS13);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_EQUAL(S2N_CERT_ERR_UNTRUSTED,
                     s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        
        s2n_stuffer_free(&chain_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_config_free(config);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /* Test validator to store the peer cert chain on the s2n connection */
    {
        struct s2n_x509_trust_store trust_store =  { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer =  { 0 };
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* Test validator to store the full cert chain from wire when verification is turned off */
        {
            struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

            struct s2n_pkey public_key_out = { 0 };
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = { 0 };

            struct s2n_x509_validator validator = { 0 };
            s2n_x509_validator_init(&validator, &trust_store, 1);
            validator.skip_cert_validation = 1;

            EXPECT_EQUAL(S2N_CERT_OK,
                        s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

            EXPECT_EQUAL(0, verify_data.callback_invoked);
            EXPECT_EQUAL(connection->secure.peer_cert_chain.size, chain_len);
            EXPECT_BYTEARRAY_EQUAL(connection->secure.peer_cert_chain.data, chain_data, connection->secure.peer_cert_chain.size);

            s2n_pkey_free(&public_key_out);
            s2n_x509_validator_wipe(&validator);
            EXPECT_SUCCESS(s2n_connection_free(connection));
        }

        /* Test validator to store only the validated cert chain when the verification succeeds */
        {
            struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

            struct s2n_pkey public_key_out = { 0 };
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = { 0 };

            struct s2n_x509_validator validator = { 0 };
            s2n_x509_validator_init(&validator, &trust_store, 1);
            EXPECT_NULL(validator.cert_chain_validated);

            EXPECT_EQUAL(S2N_CERT_OK,
                        s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

            EXPECT_EQUAL(1, verify_data.callback_invoked);
            EXPECT_NOT_NULL(validator.cert_chain_validated);

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_init(&cert_chain_stuffer, &connection->secure.peer_cert_chain));
            EXPECT_SUCCESS(s2n_stuffer_write(&cert_chain_stuffer, &connection->secure.peer_cert_chain));
 
            size_t cert_idx = 0;
            while (s2n_stuffer_data_available(&cert_chain_stuffer) && cert_idx < sk_X509_num(validator.cert_chain_validated)) {
                uint32_t cert_size_from_conn = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint24(&cert_chain_stuffer, &cert_size_from_conn));
                EXPECT_TRUE((s2n_stuffer_data_available(&cert_chain_stuffer) > cert_size_from_conn)
                                                       && (cert_size_from_conn > 0));
                uint8_t *cert_data_from_conn = s2n_stuffer_raw_read(&cert_chain_stuffer, cert_size_from_conn);
                EXPECT_NOT_NULL(cert_data_from_conn);

                X509 *cert = sk_X509_value(validator.cert_chain_validated, cert_idx);
                EXPECT_NOT_NULL(cert);
                uint8_t *cert_data_from_validator = NULL;
                int cert_size_from_validator = i2d_X509(cert, &cert_data_from_validator);
                EXPECT_TRUE(cert_size_from_validator > 0 && cert_data_from_validator != NULL);

                EXPECT_EQUAL(cert_size_from_conn, cert_size_from_validator);
                EXPECT_BYTEARRAY_EQUAL(cert_data_from_conn, cert_data_from_validator, cert_size_from_conn);
                OPENSSL_free(cert_data_from_validator);
                cert_idx++;
            }

            EXPECT_SUCCESS(s2n_pkey_free(&public_key_out));
            s2n_x509_validator_wipe(&validator);
            EXPECT_SUCCESS(s2n_connection_free(connection));
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&chain_stuffer));
        s2n_x509_trust_store_wipe(&trust_store);
    }

    END_TEST();
}
