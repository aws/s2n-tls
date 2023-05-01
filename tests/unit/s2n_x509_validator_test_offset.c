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

static int mock_time(void *data, uint64_t *timestamp)
{
    *timestamp = *(uint64_t *) data;
    return 0;
}

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

static uint8_t verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

int test_with_system_time(uint64_t system_time_nanos, s2n_error expected)
{
    DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
    s2n_x509_trust_store_init_empty(&trust_store);
    EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_OCSP_CA_CERT, NULL));

    DEFER_CLEANUP(struct s2n_x509_validator validator = { 0 }, s2n_x509_validator_wipe);
    EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 1));

    struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
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
    uint64_t timestamp_nanoseconds = system_time_nanos;
    EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, mock_time, &timestamp_nanoseconds));

    DEFER_CLEANUP(struct s2n_stuffer ocsp_data_stuffer = { 0 }, s2n_stuffer_free);
    EXPECT_SUCCESS(read_file(&ocsp_data_stuffer, S2N_OCSP_RESPONSE_EARLY_EXPIRE_DER, S2N_MAX_TEST_PEM_SIZE));
    uint32_t ocsp_data_len = s2n_stuffer_data_available(&ocsp_data_stuffer);
    EXPECT_TRUE(ocsp_data_len > 0);

    if (expected != S2N_ERR_T_OK) {
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                                        s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len),
                expected);
    } else {
        EXPECT_OK(s2n_x509_validator_validate_cert_stapled_ocsp_response(&validator, connection,
                s2n_stuffer_raw_read(&ocsp_data_stuffer, ocsp_data_len), ocsp_data_len));
    }

    EXPECT_SUCCESS(s2n_config_set_wall_clock(connection->config, old_clock, NULL));
    EXPECT_SUCCESS(s2n_connection_free(connection));
}

/**
 * Test OCSP validation at various offsets from update times
 * libcrypto ASN1 comparison calculates differences in terms of days and seconds,
 * so try mocking the system time to a collection of more than day & less
 * day differences.
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
int main(int argc, char **argv)
{
    BEGIN_TEST();
#if S2N_OCSP_STAPLING_SUPPORTED

    /* Apr 28 22:11:56 2023 GMT */
    uint64_t this_update_timestamp_nanoseconds = (uint64_t) 1682719916 * ONE_SEC_IN_NANOS;

    /* Apr 28 22:11:56 2023 GMT */
    uint64_t next_update_timestamp_nanoseconds = (uint64_t) 2082838316 * ONE_SEC_IN_NANOS;

    uint64_t one_hour_nanoseconds = (uint64_t) 60 * 60 * ONE_SEC_IN_NANOS;
    uint64_t one_day_nanoseconds = 24 * one_hour_nanoseconds;

    test_with_system_time(this_update_timestamp_nanoseconds - (one_day_nanoseconds + one_hour_nanoseconds), S2N_ERR_CERT_INVALID);
    test_with_system_time(this_update_timestamp_nanoseconds - one_hour_nanoseconds, S2N_ERR_CERT_INVALID);
    test_with_system_time(this_update_timestamp_nanoseconds + one_hour_nanoseconds, S2N_ERR_T_OK);
    test_with_system_time(this_update_timestamp_nanoseconds + (one_day_nanoseconds + one_hour_nanoseconds), S2N_ERR_T_OK);

    test_with_system_time(next_update_timestamp_nanoseconds - (one_day_nanoseconds + one_hour_nanoseconds), S2N_ERR_T_OK);
    test_with_system_time(next_update_timestamp_nanoseconds - one_hour_nanoseconds, S2N_ERR_T_OK);
    test_with_system_time(next_update_timestamp_nanoseconds + one_hour_nanoseconds, S2N_ERR_CERT_EXPIRED);
    test_with_system_time(next_update_timestamp_nanoseconds + (one_day_nanoseconds + one_hour_nanoseconds), S2N_ERR_CERT_EXPIRED);
#endif
    END_TEST();
}
