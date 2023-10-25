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

DEFINE_POINTER_CLEANUP_FUNC(X509 *, X509_free);

static int mock_time(void *data, uint64_t *timestamp)
{
    *timestamp = *(uint64_t *) data;
    return 0;
}

static int fetch_expired_after_ocsp_timestamp(void *data, uint64_t *timestamp)
{
    /* 2200-11-27 */
    *timestamp = 7283958536000000000;
    return 0;
}

static int fetch_early_expired_after_ocsp_timestamp(void *data, uint64_t *timestamp)
{
    /* 2038-01-01 */
    *timestamp = 2145920461000000000;
    return 0;
}

#if S2N_OCSP_STAPLING_SUPPORTED
static int fetch_invalid_before_ocsp_timestamp(void *data, uint64_t *timestamp)
{
    /* 2015-02-27 */
    *timestamp = 1425019604000000000;
    return 0;
}

static int fetch_not_expired_ocsp_timestamp(void *data, uint64_t *timestamp)
{
    /* 2019-03-17 */
    *timestamp = 1552824239000000000;
    return 0;
}
#endif /* S2N_OCSP_STAPLING_SUPPORTED */

static int read_file(struct s2n_stuffer *file_output, const char *path, uint32_t max_len)
{
    FILE *fd = fopen(path, "rb");
    s2n_stuffer_alloc(file_output, max_len);

    if (fd) {
        char data[1024];
        size_t r = 0;
        while ((r = fread(data, 1, sizeof(data), fd)) > 0) {
            s2n_stuffer_write_bytes(file_output, (const uint8_t *) data, (const uint32_t) r);
        }
        fclose(fd);
        return s2n_stuffer_data_available(file_output) > 0;
    }

    return -1;
}

struct host_verify_data {
    const char *name;
    uint8_t found_name;
    uint8_t callback_invoked;
};

static uint8_t verify_host_reject_everything(const char *host_name, size_t host_name_len, void *data)
{
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 0;
}

static uint8_t verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data)
{
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 1;
}

static uint8_t verify_host_verify_alt(const char *host_name, size_t host_name_len, void *data)
{
    struct host_verify_data *verify_data = (struct host_verify_data *) data;

    verify_data->callback_invoked = 1;
    if (!strcmp(host_name, verify_data->name)) {
        verify_data->found_name = 1;
        return 1;
    }

    return 0;
}

/* some tests try to mock the system time to a date post 2038. If this test is
 * run on a platform where time_t is 32 bits, the time_t will overflow, so we
 * only run these tests on platforms with a 64 bit time_t.
 */
static bool s2n_supports_large_time_t()
{
    return sizeof(time_t) == 8;
}

/* Early versions of Openssl (Openssl-1.0.2k confirmed) included a bug where UTCTime
 * formatted dates in certificates could not be compared to dates after the year 2050,
 * because Openssl would assume that the validation date was also UTCTime formatted
 * and therefore reject any date with a year after 2050.
 * This is an issue because RFC5280 requires that dates in certificates be in
 * UTCTime format for years before 2050.
 * Affected tests are modified to account for this bug.
 * See https://github.com/openssl/openssl/blob/OpenSSL_1_0_2k/crypto/x509/x509_vfy.c#L2027C1-L2027C26
 */
static bool s2n_libcrypto_supports_2050()
{
    ASN1_TIME *utc_time = ASN1_UTCTIME_set(NULL, 0);
    time_t time_2050 = 2524608000;
    int result = X509_cmp_time(utc_time, &time_2050);
    ASN1_STRING_free(utc_time);
    return (result != 0);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* The issues with 2050 only affected openssl-1.0.2 */
    if (S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0)) {
        EXPECT_TRUE(s2n_libcrypto_supports_2050());
    }

    /* test empty trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
    };

    /* test trust store from PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL);
        EXPECT_EQUAL(0, err_code);
        EXPECT_TRUE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test trust store from PEM */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        char *cert_chain = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        int err_code = s2n_x509_trust_store_add_pem(&trust_store, cert_chain);
        EXPECT_EQUAL(0, err_code);
        EXPECT_TRUE(s2n_x509_trust_store_has_certs(&trust_store));

        /* s2n_x509_trust_store_add_pem returns success when trying to add a
         * certificate that already exists in the trust store */
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, cert_chain));

        free(cert_chain);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test trust store from non-existent PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, "dskfjasdklfjsdkl", NULL);
        EXPECT_EQUAL(-1, err_code);
        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test trust store from invalid PEM file */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        int err_code = s2n_x509_trust_store_from_ca_file(&trust_store, S2N_INVALID_HEADER_KEY, NULL);
        EXPECT_EQUAL(-1, err_code);
        EXPECT_FALSE(s2n_x509_trust_store_has_certs(&trust_store));
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in unsafe mode */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    };

    /* test validator in unsafe mode, make sure max depth is honored on the read, but not an error condition */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        EXPECT_SUCCESS(s2n_x509_validator_set_max_chain_depth(&validator, 2));
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    };

    /* test validator in safe mode, but no configured trust store */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        EXPECT_FAILURE_WITH_ERRNO(s2n_x509_validator_set_max_chain_depth(&validator, 0), S2N_ERR_INVALID_ARGUMENT);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);
        EXPECT_EQUAL(0, verify_data.callback_invoked);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_URI_SANS_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        EXPECT_SUCCESS(s2n_x509_validator_set_max_chain_depth(&validator, 2));
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out),
                S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);

        EXPECT_EQUAL(0, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_UNKNOWN, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test post-2038 certificate expiration.
     *
     * The expired certificate should fail as untrusted. This test fails on
     * platforms where time_t is 4 bytes because representing dates past 2038 as
     * unix seconds overflows the time_t.
     */
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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_expired_after_ocsp_timestamp, NULL);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        int expected_errno = S2N_ERR_CERT_EXPIRED;
        /* In some cases validation may fail with a less specific error due to
         * issues with large dates, but validation does always fail. */
        if (!s2n_supports_large_time_t()) {
            expected_errno = S2N_ERR_SAFETY;
        } else if (!s2n_libcrypto_supports_2050()) {
            expected_errno = S2N_ERR_CERT_UNTRUSTED;
        }
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_validate_cert_chain(&validator, connection,
                        chain_data, chain_len, &pkey_type, &public_key_out),
                expected_errno);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_config_set_wall_clock(connection->config, old_clock, NULL);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test pre-2038 certificate expiration
     *
     * After the expiration date, the certificate should fail as untrusted. This
     * test uses pre-2038 dates for 32 bit time_t concerns
     */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT_EARLY_EXPIRE, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, fetch_early_expired_after_ocsp_timestamp, NULL));

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_validate_cert_chain(&validator, connection,
                        chain_data, chain_len, &pkey_type, &public_key_out),
                S2N_ERR_CERT_EXPIRED);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, old_clock, NULL));
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        /* alter a random byte in the certificate to make it invalid */
        chain_data[500] = (uint8_t) (chain_data[500] << 2);
        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in safe mode, with properly configured trust store, but host isn't trusted*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct host_verify_data verify_data = {
            .name = "127.0.0.1",
            .found_name = 0,
            .callback_invoked = 0,
        };

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_reject_everything, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        struct host_verify_data verify_data = {
            .name = "127.0.0.1",
            .found_name = 0,
            .callback_invoked = 0,
        };

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_reject_everything, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_connection_free(connection);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in safe mode, with properly configured trust store. host name validation succeeds */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct host_verify_data verify_data = {
            .name = "127.0.0.1",
            .found_name = 0,
            .callback_invoked = 0,
        };

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        struct host_verify_data verify_data = {
            .name = "127.0.0.1",
            .found_name = 0,
            .callback_invoked = 0,
        };

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* The default cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_pkey_free(&public_key_out);

        s2n_connection_free(connection);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in safe mode, with properly configured trust store. host name via alternative name validation succeeds
     * note: in this case, we don't have valid certs but it's enough to make sure we are properly pulling alternative names
     * from the certificate. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct host_verify_data verify_data = {
            .name = "127.0.0.1",
            .found_name = 0,
            .callback_invoked = 0,
        };
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_CLIENT_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_UNKNOWN, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in safe mode, with properly configured trust store. host name via alternative name validation fails, and
     * no Common Name validation happens as DNS alternative name is present. note: in this case, we don't have valid certs but
     * it's enough to make sure we are properly validating alternative names and common name.*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        /* Name matches CN on certificate (CN=localhost), but no match in alternative names */
        struct host_verify_data verify_data = {
            .name = "localhost",
            .found_name = 0,
            .callback_invoked = 0,
        };
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_CLIENT_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(0, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_UNKNOWN, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in safe mode, with properly configured trust store. host name via common name validation succeeds,
     * non-dns alternative names are ignored. note: in this case, we don't have valid certs but it's enough to make sure
     * we are properly validating alternative names and common name.*/
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        /* Name matches CN on certificate (CN=localhost) */
        struct host_verify_data verify_data = {
            .name = "localhost",
            .found_name = 0,
            .callback_invoked = 0,
        };
        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_NO_DNS_SANS_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(1, verify_data.found_name);
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        EXPECT_EQUAL(S2N_PKEY_TYPE_UNKNOWN, pkey_type);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };
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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_OK(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len));

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_NO_NEXT_UPDATE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_not_expired_ocsp_timestamp, NULL);

        EXPECT_OK(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len));
        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_config_set_wall_clock(connection->config, old_clock, NULL);

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        s2n_pkey_free(&public_key_out);

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_OK(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len));

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /**
     * Test invalid OCSP date range post-2038
     *
     * After the "Next Update" time in the OCSP response, the certificate should
     * fail as expired.
     */
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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_expired_after_ocsp_timestamp, NULL);

        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        if (s2n_supports_large_time_t()) {
            EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                            s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                    S2N_ERR_CERT_EXPIRED);
        } else {
            /* fetch_expired_after_ocsp_timestamp is in 2200 which is not
             * representable for 32 bit time_t's.
             */
            EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                            s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                    S2N_ERR_SAFETY);
        }

        s2n_config_set_wall_clock(connection->config, old_clock, NULL);
        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    }

    /**
     * Test invalid OCSP date range pre-2038
     *
     * This test sets the clock time to be after the expiration date of the cert
     * and after the "Next Update" field of the OCSP response.
     */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

        DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 1));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);

        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT_EARLY_EXPIRE, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, fetch_early_expired_after_ocsp_timestamp, NULL));

        DEFER_CLEANUP(struct s2n_stuffer ocsp_data_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_EARLY_EXPIRE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                S2N_ERR_CERT_EXPIRED);

        EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, old_clock, NULL));
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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
        s2n_config_set_wall_clock(connection->config, fetch_invalid_before_ocsp_timestamp, NULL);

        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                S2N_ERR_CERT_INVALID);

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        /* flip a byte right in the middle of the cert */
        uint8_t *raw_data = (uint8_t *) s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);
        raw_data[800] = (uint8_t) (raw_data[800] + 1);

        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        raw_data, ocsp_data_len),
                S2N_ERR_CERT_UNTRUSTED);

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_WILDCARD_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        uint8_t *raw_data = (uint8_t *) s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);

        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        raw_data, ocsp_data_len),
                S2N_ERR_CERT_UNTRUSTED);

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_ECDSA_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        uint8_t *raw_data = (uint8_t *) s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);

        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        raw_data, ocsp_data_len),
                S2N_ERR_CERT_UNTRUSTED);

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_ECDSA_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_WRONG_SIGNER_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);

        uint8_t *raw_data = (uint8_t *) s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len);

        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        raw_data, ocsp_data_len),
                S2N_ERR_CERT_UNTRUSTED);

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        EXPECT_EQUAL(1, verify_data.callback_invoked);
        struct s2n_stuffer ocsp_data_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_REVOKED_DER, S2N_MAX_TEST_PEM_SIZE));
        uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
        EXPECT_TRUE(ocsp_data_len > 0);
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                S2N_ERR_CERT_REVOKED);

        s2n_stuffer_free(&ocsp_data_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /**
     * Test OCSP validation at various offsets from update times.
     *
     * libcrypto ASN1 comparison calculates differences in terms of days and seconds,
     * so try mocking the system time to a collection of more than day & less
     * than day differences.
     * The T's in the below diagram represent test cases that should fail
     * The F's represent test cases that should succeed
     *    S2N_ERR_CERT_INVALID                            S2N_ERR_CERT_EXPIRED
     *          |   |                                        |   |
     *          v   v                                        v   v
     *          F   F   T   T                        T   T   F   F
     *          v   v   v   v                        v   v   v   v
     * <----------|---|---|----------------------------|---|---|--->
     *                ^                                    ^
     *       this update                                 next update
     *                |---|
     *                  one day
     *
     * If this test is failing make sure that the this_update_timestamp_nanoseconds
     * matches the actual timestamp of ocsp_response_early_expire.der
     *
     * openssl ocsp -respin ocsp_response_early_expire.der -text -noverify | grep "This Update"
     */
    {
        /* Apr 28 22:11:56 2023 GMT */
        uint64_t this_update_timestamp_nanoseconds = (uint64_t) 1682719916 * ONE_SEC_IN_NANOS;

        /* Apr 28 22:11:56 2023 GMT */
        uint64_t next_update_timestamp_nanoseconds = (uint64_t) 2082838316 * ONE_SEC_IN_NANOS;

        uint64_t one_hour_nanoseconds = (uint64_t) 60 * 60 * ONE_SEC_IN_NANOS;
        uint64_t one_day_nanoseconds = 24 * one_hour_nanoseconds;

        struct {
            uint64_t time;
            int result;
        } test_cases[] = {
            {
                    .time = this_update_timestamp_nanoseconds - (one_day_nanoseconds + one_hour_nanoseconds),
                    .result = S2N_ERR_CERT_INVALID,
            },
            {
                    .time = this_update_timestamp_nanoseconds - one_hour_nanoseconds,
                    .result = S2N_ERR_CERT_INVALID,
            },
            {
                    .time = this_update_timestamp_nanoseconds + one_hour_nanoseconds,
                    .result = S2N_ERR_OK,
            },
            {
                    .time = this_update_timestamp_nanoseconds + (one_day_nanoseconds + one_hour_nanoseconds),
                    .result = S2N_ERR_OK,
            },
            {
                    .time = next_update_timestamp_nanoseconds - (one_day_nanoseconds + one_hour_nanoseconds),
                    .result = S2N_ERR_OK,
            },
            {
                    .time = next_update_timestamp_nanoseconds - one_hour_nanoseconds,
                    .result = S2N_ERR_OK,
            },
            {
                    .time = next_update_timestamp_nanoseconds + one_hour_nanoseconds,
                    .result = S2N_ERR_CERT_EXPIRED,
            },
            {
                    .time = next_update_timestamp_nanoseconds + (one_day_nanoseconds + one_hour_nanoseconds),
                    .result = S2N_ERR_CERT_EXPIRED,
            }
        };

        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
            s2n_x509_trust_store_init_empty(&trust_store);
            EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

            DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 1));

            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(connection);

            struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
            EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_OCSP_SERVER_CERT_EARLY_EXPIRE, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

            /**
             * keep track of the old clock, because we want cert validation to happen
             * with the default system clock, and not the "mock_time" clock.
             */
            s2n_clock_time_nanoseconds old_clock = connection->config->wall_clock;
            uint64_t timestamp_nanoseconds = test_cases[i].time;
            EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, mock_time, &timestamp_nanoseconds));

            DEFER_CLEANUP(struct s2n_stuffer ocsp_data_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_EARLY_EXPIRE_DER, S2N_MAX_TEST_PEM_SIZE));
            uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
            EXPECT_TRUE(ocsp_data_len > 0);

            if (test_cases[i].result != S2N_ERR_OK) {
                EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                                s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                        test_cases[i].result);
            } else {
                EXPECT_OK(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                        s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len));
            }

            EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, old_clock, NULL));
        };
    };
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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_WILDCARD_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_WILDCARD_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_WILDCARD_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(S2N_PKEY_TYPE_UNKNOWN, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* test validator in safe mode, with default host name validator. Connection server matches the IPv6 address on the certificate. */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_IP_V6_LO_RSA_CERT, NULL));

        DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
        s2n_x509_validator_init(&validator, &trust_store, 1);

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);

        /* the provided hostname should be an empty string */
        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = "::1" };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(
                connection,
                S2N_IP_V6_LO_RSA_CERT,
                &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
    };

    /* Server matches the empty string when there are no usable identifiers in the cert. */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_WITHOUT_CN_RSA_CERT, NULL));

        DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
        s2n_x509_validator_init(&validator, &trust_store, 1);

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);

        /* the provided hostname should be an empty string */
        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = "" };
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_verify_alt, &verify_data));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(
                connection,
                S2N_WITHOUT_CN_RSA_CERT,
                &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
    };

    /* test validator in safe mode, with default host name validator. No connection server name supplied. */
    {
        struct s2n_x509_trust_store trust_store;
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_RSA_2048_SHA256_WILDCARD_CERT, NULL));

        struct s2n_x509_validator validator;
        s2n_x509_validator_init(&validator, &trust_store, 1);

        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(
                s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_SHA256_WILDCARD_CERT, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(S2N_PKEY_TYPE_UNKNOWN, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* Test trust store in a configuration can handle invalid PEM without crashing */
    {
        struct s2n_config *cfg = s2n_config_new();
        s2n_config_add_pem_to_trust_store(cfg, "");
        s2n_config_free(cfg);
        /* Expect no crash. */
    };

    /* Test one trailing byte in cert validator */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct s2n_stuffer chain_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&chain_stuffer, S2N_ONE_TRAILING_BYTE_CERT_BIN, S2N_MAX_TEST_PEM_SIZE));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
        s2n_stuffer_free(&chain_stuffer);
        EXPECT_EQUAL(S2N_PKEY_TYPE_RSA, pkey_type);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    };

    /* Test more trailing bytes in cert validator for negative case */
    {
        struct s2n_x509_validator validator;
        s2n_x509_validator_init_no_x509_validation(&validator);
        struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(connection);

        struct s2n_stuffer chain_stuffer = { 0 };
        EXPECT_SUCCESS(read_file(&chain_stuffer, S2N_FOUR_TRAILING_BYTE_CERT_BIN, S2N_MAX_TEST_PEM_SIZE));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        /* Expect to return S2N_CERT_ERR_UNTRUSTED */
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        s2n_stuffer_free(&chain_stuffer);
        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);
        s2n_x509_validator_wipe(&validator);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_PKCS1_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* This cert chain includes a SHA1 signature, so the security policy must allow SHA1 cert signatures. */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        validator.skip_cert_validation = 1;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_config_free(config);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

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

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_RSA_2048_PKCS1_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_pkey public_key_out;
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_UNTRUSTED);

        s2n_connection_free(connection);
        s2n_pkey_free(&public_key_out);

        s2n_config_free(config);
        s2n_x509_validator_wipe(&validator);
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* Test trust store can be wiped */
    {
        /* Wipe new s2n_config, which is initialized with certs from the system default locations. */
        {
            struct s2n_config *cfg = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_FALSE(s2n_x509_trust_store_has_certs(&cfg->trust_store));
            s2n_config_free(cfg);
        };

        /* Wipe repeatedly without crash */
        {
            struct s2n_config *cfg = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_FALSE(s2n_x509_trust_store_has_certs(&cfg->trust_store));
            s2n_config_free(cfg);
        };

        /* Wipe after setting verification location */
        {
            struct s2n_config *cfg = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(cfg, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_TRUE(s2n_x509_trust_store_has_certs(&cfg->trust_store));

            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_FALSE(s2n_x509_trust_store_has_certs(&cfg->trust_store));
            s2n_config_free(cfg);
        };

        /* Set verification location after wipe */
        {
            struct s2n_config *cfg = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_FALSE(s2n_x509_trust_store_has_certs(&cfg->trust_store));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(cfg, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_TRUE(s2n_x509_trust_store_has_certs(&cfg->trust_store));
            s2n_config_free(cfg);
        };

        /* Wipe after adding PEM */
        {
            struct s2n_config *cfg = s2n_config_new();
            char *cert_chain = NULL;
            EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(cfg, cert_chain));
            EXPECT_TRUE(s2n_x509_trust_store_has_certs(&cfg->trust_store));

            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_FALSE(s2n_x509_trust_store_has_certs(&cfg->trust_store));
            free(cert_chain);
            s2n_config_free(cfg);
        };

        /* Add PEM after wipe */
        {
            struct s2n_config *cfg = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_wipe_trust_store(cfg));
            EXPECT_FALSE(s2n_x509_trust_store_has_certs(&cfg->trust_store));

            char *cert_chain = NULL;
            EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(cfg, cert_chain));
            EXPECT_TRUE(s2n_x509_trust_store_has_certs(&cfg->trust_store));
            free(cert_chain);
            s2n_config_free(cfg);
        };
    };

    /* Ensure that non-root certificates added to the trust store are trusted */
    {
        const char *non_root_cert_path = S2N_RSA_2048_PKCS1_LEAF_CERT;

#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0)
        /* Ensure that the test certificate isn't self-signed, and is therefore not a root.
         *
         * The X509_get_extension_flags API wasn't added to OpenSSL until 1.1.0.
         */
        {
            const char *non_root_key_path = S2N_RSA_2048_PKCS1_KEY;

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, non_root_cert_path, non_root_key_path));
            struct s2n_cert *cert = NULL;
            EXPECT_SUCCESS(s2n_cert_chain_get_cert(chain_and_key, &cert, 0));
            EXPECT_NOT_NULL(cert);

            /* Use the s2n_cert to convert the PEM to ASN.1. */
            const uint8_t *asn1_data = NULL;
            uint32_t asn1_len = 0;
            EXPECT_SUCCESS(s2n_cert_get_der(cert, &asn1_data, &asn1_len));
            EXPECT_NOT_NULL(asn1_data);

            /* Parse the ASN.1 data with the libcrypto */
            DEFER_CLEANUP(X509 *x509 = d2i_X509(NULL, &asn1_data, asn1_len), X509_free_pointer);
            EXPECT_NOT_NULL(x509);

            /* Ensure that the self-signed flag isn't set */
            uint32_t extension_flags = X509_get_extension_flags(x509);
            EXPECT_EQUAL(extension_flags & EXFLAG_SS, 0);
        }
#endif

        /* Test s2n_config_set_verification_ca_location */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, non_root_cert_path, NULL));

            DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));
            EXPECT_SUCCESS(s2n_set_server_name(connection, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, non_root_cert_path, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                    &public_key_out));
        }

        /* Test s2n_config_add_pem_to_trust_store */
        {
            char non_root_cert_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_read_test_pem(non_root_cert_path, non_root_cert_pem, S2N_MAX_TEST_PEM_SIZE));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(config, non_root_cert_pem));

            DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));
            EXPECT_SUCCESS(s2n_set_server_name(connection, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, non_root_cert_path, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                    &public_key_out));
        }

        /* Test system trust store
         *
         * This test uses the SSL_CERT_FILE environment variable to override the system trust store
         * location, which isn't supported by LibreSSL.
         */
        if (!s2n_libcrypto_is_libressl()) {
            /* Override the system cert file with the non-root test cert. */
            EXPECT_SUCCESS(setenv("SSL_CERT_FILE", non_root_cert_path, 1));
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

            DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(connection, "default"));
            EXPECT_SUCCESS(s2n_set_server_name(connection, "s2nTestServer"));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, non_root_cert_path, &cert_chain_stuffer));
            uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                    &public_key_out));

            EXPECT_SUCCESS(unsetenv("SSL_CERT_FILE"));
        }
    }

    END_TEST();
}
