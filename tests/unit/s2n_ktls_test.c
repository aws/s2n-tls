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

#include <stdlib.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const struct s2n_security_policy *default_security_policy, *tls13_security_policy, *fips_security_policy;
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_tls13", &tls13_security_policy));
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_fips", &fips_security_policy));
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &default_security_policy));

    char cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert, S2N_MAX_TEST_PEM_SIZE));
    char key[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, key, S2N_MAX_TEST_PEM_SIZE));

    /* config default kTLS mode */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_EQUAL(config->ktls_mode_requested, S2N_KTLS_MODE_DISABLED);
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DISABLED));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DUPLEX));
    };

    /* request config kTLS mode
     *
     * Enabling TX and RX modes is additive and equals Duplex
     */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DUPLEX));

        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_TX));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_RX));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DUPLEX));
    };

    /* disallow kTLS disable requested
     *
     * kTLS cannot be disabled once it has been enabled
     */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_DUPLEX));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_TX));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_RX));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DUPLEX));

        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_DISABLED));
        EXPECT_FALSE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_TX));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_RX));
        EXPECT_TRUE(s2n_config_is_ktls_requested(config, S2N_KTLS_MODE_DUPLEX));
    };

    /* connection default kTLS mode */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));
        EXPECT_TRUE(conn->managed_send_io);
        EXPECT_TRUE(conn->managed_recv_io);

        EXPECT_EQUAL(conn->ktls_mode_enabled, S2N_KTLS_MODE_DISABLED);
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DISABLED));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DUPLEX));
    };

    /* enable kTLS modes
     *
     * Enabling TX and RX modes is additive and equals Duplex
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));
        EXPECT_TRUE(conn->managed_send_io);
        EXPECT_TRUE(conn->managed_recv_io);

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_DUPLEX));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_EQUAL(conn->ktls_mode_enabled, S2N_KTLS_MODE_DISABLED);

        EXPECT_OK(s2n_connection_mark_ktls_enabled(conn, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DUPLEX));

        EXPECT_OK(s2n_connection_mark_ktls_enabled(conn, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_TX));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_RX));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DUPLEX));
    };

    /* enable kTLS duplex */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));
        EXPECT_TRUE(conn->managed_send_io);
        EXPECT_TRUE(conn->managed_recv_io);

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_DUPLEX));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_EQUAL(conn->ktls_mode_enabled, S2N_KTLS_MODE_DISABLED);

        EXPECT_OK(s2n_connection_mark_ktls_enabled(conn, S2N_KTLS_MODE_DUPLEX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DISABLED));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_TX));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_RX));
        EXPECT_TRUE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DUPLEX));
    };

    /* disabling kTLS, once enabled is not supported so confirm this returns an error
     *
     * Note: This behavior might change if we introduce a kernel patch which
     * support user space fallback from kTLS.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));
        EXPECT_TRUE(conn->managed_send_io);
        EXPECT_TRUE(conn->managed_recv_io);

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_ktls_enable(config, S2N_KTLS_MODE_DUPLEX));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_EQUAL(conn->ktls_mode_enabled, S2N_KTLS_MODE_DISABLED);

        EXPECT_ERROR(s2n_connection_mark_ktls_enabled(conn, S2N_KTLS_MODE_DISABLED));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_TX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_RX));
        EXPECT_FALSE(s2n_connection_is_ktls_enabled(conn, S2N_KTLS_MODE_DUPLEX));
    };

    END_TEST();
}
