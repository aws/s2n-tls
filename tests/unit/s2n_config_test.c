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

#include "tls/s2n_config.h"

#include <stdlib.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_internal.h"
#include "tls/s2n_record.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"
#include "unstable/npn.h"
#include "utils/s2n_map.h"

#define S2N_TEST_MAX_SUPPORTED_GROUPS_COUNT 30

/* forward declaration */
int s2n_config_build_domain_name_to_cert_map(struct s2n_config *config, struct s2n_cert_chain_and_key *cert_key_pair);

static int s2n_test_select_psk_identity_callback(struct s2n_connection *conn, void *context,
        struct s2n_offered_psk_list *psk_identity_list)
{
    return S2N_SUCCESS;
}

static int s2n_test_reneg_req_cb(struct s2n_connection *conn, void *context, s2n_renegotiate_response *response)
{
    return S2N_SUCCESS;
}

static int s2n_test_crl_lookup_cb(struct s2n_crl_lookup *lookup, void *context)
{
    return S2N_SUCCESS;
}

static int s2n_test_cert_validation_cb(struct s2n_connection *conn, struct s2n_cert_validation_info *info, void *context)
{
    return S2N_SUCCESS;
}

static int s2n_test_async_pkey_fn(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

    const struct s2n_security_policy *default_security_policy = NULL, *tls13_security_policy = NULL, *fips_security_policy = NULL;
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_tls13", &tls13_security_policy));
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_fips", &fips_security_policy));
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &default_security_policy));

    char cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert, S2N_MAX_TEST_PEM_SIZE));
    char key[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, key, S2N_MAX_TEST_PEM_SIZE));

    /* Test: s2n_config_new and tls13_default_config match */
    {
        struct s2n_config *config = NULL, *default_config = NULL;

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_NOT_NULL(default_config = s2n_fetch_default_config());

        /* s2n_config_new() matches s2n_fetch_default_config() */
        EXPECT_EQUAL(default_config->security_policy, config->security_policy);
        EXPECT_EQUAL(default_config->security_policy->signature_preferences, config->security_policy->signature_preferences);
        EXPECT_EQUAL(default_config->client_cert_auth_type, config->client_cert_auth_type);

        /* Calling s2n_fetch_default_config() repeatedly returns the same object */
        EXPECT_EQUAL(default_config, s2n_fetch_default_config());

        /* TLS1.3 default does not match non-TLS1.3 default */
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        EXPECT_NOT_EQUAL(default_config, s2n_fetch_default_config());
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Connections created with default configs */
    {
        /* For TLS1.2 */
        if (!s2n_is_in_fips_mode()) {
            struct s2n_connection *conn = NULL;
            const struct s2n_security_policy *security_policy = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->config, s2n_fetch_default_config());

            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_EQUAL(security_policy, default_security_policy);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* For TLS1.3 */
        {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            struct s2n_connection *conn = NULL;
            const struct s2n_security_policy *security_policy = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->config, s2n_fetch_default_config());

            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_EQUAL(security_policy, tls13_security_policy);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        };

        /* For fips */
        if (s2n_is_in_fips_mode()) {
            struct s2n_connection *conn = NULL;
            const struct s2n_security_policy *security_policy = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->config, s2n_fetch_default_config());

            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_EQUAL(security_policy, fips_security_policy);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        }
    };

    /* Test for s2n_config_new() and tls 1.3 behavior */
    {
        if (!s2n_is_in_fips_mode()) {
            struct s2n_config *config = NULL;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_EQUAL(config->security_policy, default_security_policy);
            EXPECT_SUCCESS(s2n_config_free(config));

            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_EQUAL(config->security_policy, tls13_security_policy);
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        }
    };

    /* Test setting the callback to select PSK identity */
    {
        struct s2n_config *config = NULL;
        EXPECT_NOT_NULL(config = s2n_config_new());
        uint8_t context = 13;

        /* Safety check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_psk_selection_callback(
                                          NULL, s2n_test_select_psk_identity_callback, &context),
                S2N_ERR_NULL);
        EXPECT_NULL(config->psk_selection_cb);
        EXPECT_NULL(config->psk_selection_ctx);

        EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(config, s2n_test_select_psk_identity_callback, &context));
        EXPECT_EQUAL(config->psk_selection_cb, s2n_test_select_psk_identity_callback);
        EXPECT_EQUAL(config->psk_selection_ctx, &context);

        EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(config, NULL, NULL));
        EXPECT_NULL(config->psk_selection_cb);
        EXPECT_NULL(config->psk_selection_ctx);

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /*Test s2n_connection_set_config */
    {
        /* Test that tickets_to_send is set correctly */
        {
            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_config *config = NULL;
            uint8_t num_tickets = 1;

            EXPECT_NOT_NULL(config = s2n_config_new());

            config->initial_tickets_to_send = num_tickets;

            EXPECT_EQUAL(conn->tickets_to_send, 0);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_EQUAL(conn->tickets_to_send, num_tickets);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that PSK type is set correctly */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_EQUAL(config->psk_mode, S2N_PSK_MODE_RESUMPTION);

            /* Overrides connection value */
            {
                conn->config = NULL;
                conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_RESUMPTION);
                EXPECT_FALSE(conn->psk_mode_overridden);
            };

            /* Does not override connection value if conn->override_psk_mode set */
            {
                conn->config = NULL;
                conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;
                conn->psk_mode_overridden = true;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_EXTERNAL);
                EXPECT_TRUE(conn->psk_mode_overridden);
                conn->psk_mode_overridden = false;
            };

            /* Does not override connection value if PSKs already set */
            {
                conn->config = NULL;
                DEFER_CLEANUP(struct s2n_psk *test_external_psk = s2n_test_psk_new(conn), s2n_psk_free);
                EXPECT_SUCCESS(s2n_connection_append_psk(conn, test_external_psk));
                EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_EXTERNAL);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_EXTERNAL);
                EXPECT_FALSE(conn->psk_mode_overridden);
            };

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test that security policy validation is enforced on the config */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *invalid_cert = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&invalid_cert, "rsae", "pss", "4096", "sha384"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, invalid_cert));
            struct s2n_security_policy rfc9151_applied_locally = security_policy_rfc9151;
            rfc9151_applied_locally.certificate_preferences_apply_locally = true;
            config->security_policy = &rfc9151_applied_locally;

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_config(conn, config), S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        };
    };

    /* s2n_config_set_session_tickets_onoff */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_session_tickets_onoff(NULL, true), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_session_tickets_onoff(NULL, false), S2N_ERR_NULL);

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));
        EXPECT_TRUE(config->use_tickets);
        EXPECT_EQUAL(config->initial_tickets_to_send, 1);

        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, false));
        EXPECT_FALSE(config->use_tickets);
        EXPECT_EQUAL(config->initial_tickets_to_send, 1);

        config->initial_tickets_to_send = 10;
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));
        EXPECT_TRUE(config->use_tickets);
        EXPECT_EQUAL(config->initial_tickets_to_send, 10);

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* s2n_config_set_context */
    /* s2n_config_get_context */
    {
        uint8_t context = 42;
        uint8_t other = 123;
        void *returned_context = NULL;

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_get_ctx(config, &returned_context));
        EXPECT_NULL(returned_context);

        EXPECT_SUCCESS(s2n_config_set_ctx(config, &context));
        EXPECT_SUCCESS(s2n_config_get_ctx(config, &returned_context));
        EXPECT_NOT_NULL(returned_context);

        EXPECT_EQUAL(*((uint8_t *) returned_context), context);
        EXPECT_NOT_EQUAL(*((uint8_t *) returned_context), other);

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test s2n_config_set_extension_data */
    {
        uint8_t extension_data[] = "extension data";

        /* Test s2n_config_set_extension_data can be called for owned cert chains */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert, key));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));

            EXPECT_SUCCESS(s2n_config_set_extension_data(config, S2N_EXTENSION_OCSP_STAPLING,
                    extension_data, sizeof(extension_data)));
            EXPECT_EQUAL(s2n_config_get_single_default_cert(config)->ocsp_status.size, sizeof(extension_data));
        };

        /* Test s2n_config_set_extension_data can't be called for unowned cert chains */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));

            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_extension_data(config, S2N_EXTENSION_OCSP_STAPLING,
                                              extension_data, sizeof(extension_data)),
                    S2N_ERR_CERT_OWNERSHIP);
            EXPECT_EQUAL(s2n_config_get_single_default_cert(config)->ocsp_status.size, 0);
            EXPECT_EQUAL(chain->ocsp_status.size, 0);
        };
    };

    /* Test s2n_config_free_cert_chain_and_key */
    {
        /* Chain owned by application */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_APP_OWNED);

            /* No-op for application-owned chains */
            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_APP_OWNED);

            /* Still no-op if called again */
            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
        };

        /* Chain owned by application and freed too early:
         * This is arguably incorrect behavior, but did not cause errors in the past.
         * We should continue to ensure it doesn't cause any errors.
         */
        {
            struct s2n_cert_chain_and_key *chain = NULL;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_APP_OWNED);

            /* Free the chain early */
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain));

            /* No-op for application-owned chains */
            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_APP_OWNED);

            /* No-op if called again */
            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
        };

        /* Chain owned by library */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert, key));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_LIB_OWNED);

            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_NOT_OWNED);

            /* No-op if called again */
            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NULL(s2n_config_get_single_default_cert(config));
        };

        /* Switch from library-owned certs to application-owned certs */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert, key));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_LIB_OWNED);

            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
            EXPECT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_NOT_OWNED);

            /* Now add an application-owned chain */
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain));
            EXPECT_SUCCESS(s2n_config_free_cert_chain_and_key(config));
        };
    };

    /* Test s2n_config_set_cert_chain_and_key_defaults */
    {
        /* Succeeds if chains owned by app */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_1 = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_1,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_2 = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_2,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_1));
            EXPECT_EQUAL(s2n_config_get_single_default_cert(config), chain_1);
            EXPECT_EQUAL(config->cert_ownership, S2N_APP_OWNED);

            EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(config, &chain_2, 1));
            EXPECT_EQUAL(s2n_config_get_single_default_cert(config), chain_2);
            EXPECT_EQUAL(config->cert_ownership, S2N_APP_OWNED);
        };

        /* Fails if chains owned by library */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert, key));
            EXPECT_NOT_NULL(s2n_config_get_single_default_cert(config));
            EXPECT_EQUAL(config->cert_ownership, S2N_LIB_OWNED);

            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cert_chain_and_key_defaults(
                                              config, &chain, 1),
                    S2N_ERR_CERT_OWNERSHIP);
        };
    };

    /* Test s2n_config_set_send_buffer_size */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            EXPECT_EQUAL(config->send_buffer_size_override, 0);
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_send_buffer_size(NULL, S2N_MIN_SEND_BUFFER_SIZE), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_send_buffer_size(config, 0), S2N_ERR_INVALID_ARGUMENT);
            EXPECT_EQUAL(config->send_buffer_size_override, 0);
        };

        /* Default applied to connection */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_EQUAL(config->send_buffer_size_override, 0);
            EXPECT_FALSE(conn->multirecord_send);
        };

        /* Custom applied to connection */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, S2N_MIN_SEND_BUFFER_SIZE));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_EQUAL(config->send_buffer_size_override, S2N_MIN_SEND_BUFFER_SIZE);
            EXPECT_TRUE(conn->multirecord_send);
        };
    };

    /* Test s2n_config_set_verify_after_sign */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_FALSE(config->verify_after_sign);

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_verify_after_sign(NULL, S2N_VERIFY_AFTER_SIGN_ENABLED), S2N_ERR_NULL);

        /* Invalid mode */
        config->verify_after_sign = true;
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_verify_after_sign(config, UINT8_MAX), S2N_ERR_INVALID_ARGUMENT);
        EXPECT_TRUE(config->verify_after_sign);
        config->verify_after_sign = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_verify_after_sign(config, UINT8_MAX), S2N_ERR_INVALID_ARGUMENT);
        EXPECT_FALSE(config->verify_after_sign);

        /* Set and unset */
        EXPECT_SUCCESS(s2n_config_set_verify_after_sign(config, S2N_VERIFY_AFTER_SIGN_ENABLED));
        EXPECT_TRUE(config->verify_after_sign);
        EXPECT_SUCCESS(s2n_config_set_verify_after_sign(config, S2N_VERIFY_AFTER_SIGN_DISABLED));
        EXPECT_FALSE(config->verify_after_sign);
    };

    /* Test s2n_config_set_renegotiate_request_cb */
    {
        uint8_t context = 0;
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        /* Unset by default */
        EXPECT_EQUAL(config->renegotiate_request_cb, NULL);
        EXPECT_EQUAL(config->renegotiate_request_ctx, NULL);

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_renegotiate_request_cb(NULL, s2n_test_reneg_req_cb, &context), S2N_ERR_NULL);
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, NULL, &context));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_test_reneg_req_cb, NULL));

        /* Set */
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_test_reneg_req_cb, &context));
        EXPECT_EQUAL(config->renegotiate_request_cb, s2n_test_reneg_req_cb);
        EXPECT_EQUAL(config->renegotiate_request_ctx, &context);

        /* Unset */
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, NULL, NULL));
        EXPECT_EQUAL(config->renegotiate_request_cb, NULL);
        EXPECT_EQUAL(config->renegotiate_request_ctx, NULL);
    };

    /* Test s2n_config_set_npn */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_FALSE(config->npn_supported);

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_npn(NULL, true), S2N_ERR_NULL);

        /* Set and unset */
        EXPECT_SUCCESS(s2n_config_set_npn(config, true));
        EXPECT_TRUE(config->npn_supported);
        EXPECT_SUCCESS(s2n_config_set_npn(config, false));
        EXPECT_FALSE(config->npn_supported);
    };

    /* Test s2n_config_set_crl_lookup_cb */
    {
        uint8_t context = 0;
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        /* Unset by default */
        EXPECT_EQUAL(config->crl_lookup_cb, NULL);
        EXPECT_EQUAL(config->crl_lookup_ctx, NULL);

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_crl_lookup_cb(NULL, s2n_test_crl_lookup_cb, &context), S2N_ERR_NULL);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, NULL, &context));
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, s2n_test_crl_lookup_cb, NULL));

        /* Set */
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, s2n_test_crl_lookup_cb, &context));
        EXPECT_EQUAL(config->crl_lookup_cb, s2n_test_crl_lookup_cb);
        EXPECT_EQUAL(config->crl_lookup_ctx, &context);

        /* Unset */
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, NULL, NULL));
        EXPECT_EQUAL(config->crl_lookup_cb, NULL);
        EXPECT_EQUAL(config->crl_lookup_ctx, NULL);
    };

    /* Test s2n_config_set_cert_validation_cb */
    {
        uint8_t context = 0;
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        /* Unset by default */
        EXPECT_EQUAL(config->cert_validation_cb, NULL);
        EXPECT_EQUAL(config->cert_validation_ctx, NULL);

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cert_validation_cb(NULL, s2n_test_cert_validation_cb, &context),
                S2N_ERR_NULL);
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, NULL, &context));
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, s2n_test_cert_validation_cb, NULL));

        /* Set */
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, s2n_test_cert_validation_cb, &context));
        EXPECT_EQUAL(config->cert_validation_cb, s2n_test_cert_validation_cb);
        EXPECT_EQUAL(config->cert_validation_ctx, &context);

        /* Unset */
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config, NULL, NULL));
        EXPECT_EQUAL(config->cert_validation_cb, NULL);
        EXPECT_EQUAL(config->cert_validation_ctx, NULL);
    };

    /* Test s2n_config_set_status_request_type */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        s2n_mode mode = modes[mode_i];

        if (!s2n_x509_ocsp_stapling_supported()) {
            break;
        }

        /* request_ocsp_status should be false by default */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_FALSE(config->ocsp_status_requested_by_user);
            EXPECT_FALSE(config->ocsp_status_requested_by_s2n);

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(mode), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_FALSE(conn->request_ocsp_status);
        };

        /* request_ocsp_status should be true if set via s2n_config_set_status_request_type */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP));
            EXPECT_TRUE(config->ocsp_status_requested_by_user);
            EXPECT_FALSE(config->ocsp_status_requested_by_s2n);

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(mode), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_TRUE(conn->request_ocsp_status);
        };

        /* ocsp_status_requested_by_s2n can be set in s2n_config_set_verification_ca_location. For
         * backwards compatibility, this should tell clients to request OCSP stapling. However, this
         * API should not tell servers to request OCSP stapling.
         */
        for (int api_configuration_i = 0; api_configuration_i < 3; api_configuration_i++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            switch (api_configuration_i) {
                case 0:
                    EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
                    break;
                case 1:
                    /* If a user intentionally disables OCSP stapling, s2n_config_set_verification_ca_location
                     * should not re-enable it for servers.
                     */
                    EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_NONE));
                    EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
                    break;
                default:
                    EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP));
                    EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_NONE));
                    EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
                    break;
            }

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(mode), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            if (mode == S2N_CLIENT) {
                EXPECT_TRUE(conn->request_ocsp_status);
            } else {
                EXPECT_FALSE(conn->request_ocsp_status);
            }
        };

        /* Calling s2n_config_set_status_request_type with S2N_STATUS_REQUEST_OCSP should enable OCSP
         * status requests, regardless of s2n_config_set_verification_ca_location.
         */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(mode), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_TRUE(conn->request_ocsp_status);
        };

        /* Calling s2n_config_set_status_request_type with S2N_STATUS_REQUEST_NONE should disable OCSP
         * status requests, regardless of s2n_config_set_verification_ca_location.
         */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_NONE));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(mode), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_FALSE(conn->request_ocsp_status);
        };
    };

    /* Test s2n_config_add_cert_chain */
    {
        uint32_t pem_len = 0;
        uint8_t pem_bytes[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                pem_bytes, &pem_len, sizeof(pem_bytes)));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain(config, pem_bytes, pem_len));
        EXPECT_TRUE(config->no_signing_key);
        EXPECT_EQUAL(config->cert_ownership, S2N_LIB_OWNED);

        struct s2n_cert_chain_and_key *chain = s2n_config_get_single_default_cert(config);
        POSIX_ENSURE_REF(chain);
        EXPECT_FAILURE(s2n_pkey_check_key_exists(chain->private_key));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_config(conn, config), S2N_ERR_NO_PRIVATE_KEY);
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, s2n_test_async_pkey_fn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
    };

    /* Test loading system certs */
    {
        /* s2n_config_load_system_certs safety */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_load_system_certs(NULL), S2N_ERR_NULL);
        }

        /* s2n_config_new_minimal should not load system certs */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_NULL(config->trust_store.trust_store);
            EXPECT_FALSE(config->trust_store.loaded_system_certs);

            /* System certs can be loaded onto the minimal config */
            EXPECT_SUCCESS(s2n_config_load_system_certs(config));
            EXPECT_NOT_NULL(config->trust_store.trust_store);
            EXPECT_TRUE(config->trust_store.loaded_system_certs);

            /* Attempting to load system certs multiple times on the same config should error */
            for (int i = 0; i < 20; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_config_load_system_certs(config), S2N_ERR_X509_TRUST_STORE);
                EXPECT_TRUE(config->trust_store.loaded_system_certs);
            }
        }

        /* s2n_config_new should load system certs */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_NOT_NULL(config->trust_store.trust_store);
            EXPECT_TRUE(config->trust_store.loaded_system_certs);

            /* Attempting to load system certs multiple times on the same config should error */
            for (int i = 0; i < 20; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_config_load_system_certs(config), S2N_ERR_X509_TRUST_STORE);
                EXPECT_TRUE(config->trust_store.loaded_system_certs);
            }
        }

        /* The default config should load system certs */
        {
            struct s2n_config *config = s2n_fetch_default_config();
            EXPECT_NOT_NULL(config);
            EXPECT_TRUE(config->trust_store.loaded_system_certs);
        }

        /* System certs can be loaded again after wiping the trust store */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            for (int i = 0; i < 20; i++) {
                /* System certs were already loaded, so an attempt to load them should fail */
                EXPECT_NOT_NULL(config->trust_store.trust_store);
                EXPECT_TRUE(config->trust_store.loaded_system_certs);
                EXPECT_FAILURE_WITH_ERRNO(s2n_config_load_system_certs(config), S2N_ERR_X509_TRUST_STORE);

                EXPECT_SUCCESS(s2n_config_wipe_trust_store(config));

                /* The trust store is cleared after a wipe, so it should be possible to load system certs again */
                EXPECT_FALSE(config->trust_store.loaded_system_certs);
                EXPECT_SUCCESS(s2n_config_load_system_certs(config));
                EXPECT_TRUE(config->trust_store.loaded_system_certs);
            }
        }

        /* Ensure that system certs are properly loaded into the X509_STORE.
         *
         * The API used to retrieve the contents of an X509_STORE, X509_STORE_get0_objects,
         * wasn't added until OpenSSL 1.1.0.
         */
#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0)
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_NULL(config->trust_store.trust_store);
            EXPECT_FALSE(config->trust_store.loaded_system_certs);

            /* Initialize the X509_STORE by adding a cert */
            EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&config->trust_store, S2N_RSA_PSS_2048_SHA256_CA_CERT, NULL));
            EXPECT_NOT_NULL(config->trust_store.trust_store);
            EXPECT_FALSE(config->trust_store.loaded_system_certs);

            /* The X509_STORE should only contain the single cert that was added. */
            STACK_OF(X509_OBJECT) *x509_store_contents = X509_STORE_get0_objects(config->trust_store.trust_store);
            EXPECT_NOT_NULL(x509_store_contents);
            int initial_contents_count = sk_X509_OBJECT_num(x509_store_contents);
            EXPECT_EQUAL(initial_contents_count, 1);

            /* Override the system cert file to guarantee that a system cert will be loaded */
            EXPECT_SUCCESS(setenv("SSL_CERT_FILE", S2N_SHA1_ROOT_SIGNATURE_CA_CERT, 1));

            /* Load the system cert into the store */
            EXPECT_SUCCESS(s2n_config_load_system_certs(config));
            EXPECT_TRUE(config->trust_store.loaded_system_certs);
            int system_certs_contents_count = sk_X509_OBJECT_num(x509_store_contents);

            /* LibreSSL doesn't use the SSL_CERT_FILE environment variable to set the system cert location,
             * so we don't know how many system certs will be loaded, if any.
             */
            if (!s2n_libcrypto_is_libressl()) {
                EXPECT_EQUAL(system_certs_contents_count, initial_contents_count + 1);
            }

            /* Additional calls to s2n_config_load_default_certs should not add additional certs to the store */
            for (int i = 0; i < 20; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_config_load_system_certs(config), S2N_ERR_X509_TRUST_STORE);
                EXPECT_TRUE(config->trust_store.loaded_system_certs);
                int additional_call_contents_count = sk_X509_OBJECT_num(x509_store_contents);
                EXPECT_TRUE(additional_call_contents_count == system_certs_contents_count);
            }

            EXPECT_SUCCESS(unsetenv("SSL_CERT_FILE"));
        }
#endif

        /* Self-talk tests */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            /* Ensure a handshake succeeds with a minimal server config and no mutual auth */
            {
                DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new_minimal(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(server_config);
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

                DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(client_config);
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
                EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

                struct s2n_test_io_pair io_pair = { 0 };
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

                EXPECT_FALSE(server_config->trust_store.loaded_system_certs);
                EXPECT_NULL(server_config->trust_store.trust_store);

                EXPECT_FALSE(client_config->trust_store.loaded_system_certs);
                EXPECT_NOT_NULL(client_config->trust_store.trust_store);

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            }

            /* Ensure a handshake fails gracefully with an uninitialized trust store */
            {
                DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new_minimal(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(server_config);
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

                DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(), s2n_config_ptr_free);
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
                EXPECT_NOT_NULL(client_config);

                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
                EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

                struct s2n_test_io_pair io_pair = { 0 };
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

                EXPECT_FALSE(server_config->trust_store.loaded_system_certs);
                EXPECT_NULL(server_config->trust_store.trust_store);

                EXPECT_FALSE(client_config->trust_store.loaded_system_certs);
                EXPECT_NULL(client_config->trust_store.trust_store);

                /* The client should fail to validate the server's certificate without an initialized trust store */
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        S2N_ERR_CERT_UNTRUSTED);
            }
        }
    }

    /* s2n_config_disable_x509_time_verification tests */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_disable_x509_time_verification(NULL), S2N_ERR_NULL);

        /* Ensure s2n_config_disable_x509_time_verification sets the proper state */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_EQUAL(config->disable_x509_time_validation, false);

            EXPECT_SUCCESS(s2n_config_disable_x509_time_verification(config));
            EXPECT_EQUAL(config->disable_x509_time_validation, true);
        }
    }

    /* Test s2n_config_get_supported_groups */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            uint16_t supported_groups[S2N_TEST_MAX_SUPPORTED_GROUPS_COUNT] = { 0 };
            uint16_t supported_groups_count = 0;

            int ret = s2n_config_get_supported_groups(NULL, supported_groups, s2n_array_len(supported_groups),
                    &supported_groups_count);
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_NULL);
            EXPECT_EQUAL(supported_groups_count, 0);

            ret = s2n_config_get_supported_groups(config, NULL, s2n_array_len(supported_groups), &supported_groups_count);
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_NULL);
            EXPECT_EQUAL(supported_groups_count, 0);

            ret = s2n_config_get_supported_groups(config, supported_groups, s2n_array_len(supported_groups), NULL);
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_NULL);
            EXPECT_EQUAL(supported_groups_count, 0);
        }

        /* Error if the provided supported groups array is too small */
        {
            /* Test a policy with and without PQ kem groups */
            const char *policies[] = {
                "20170210",
                "PQ-TLS-1-2-2023-10-07",
            };

            for (size_t i = 0; i < s2n_array_len(policies); i++) {
                DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(config);
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, policies[i]));

                uint32_t policy_groups_count = 0;
                EXPECT_OK(s2n_kem_preferences_groups_available(config->security_policy->kem_preferences,
                        &policy_groups_count));
                policy_groups_count += config->security_policy->ecc_preferences->count;
                EXPECT_TRUE(policy_groups_count > 0);

                uint16_t supported_groups[S2N_TEST_MAX_SUPPORTED_GROUPS_COUNT] = { 0 };
                uint16_t supported_groups_count = 11;
                for (size_t invalid_count = 0; invalid_count < policy_groups_count; invalid_count++) {
                    int ret = s2n_config_get_supported_groups(config, supported_groups, invalid_count,
                            &supported_groups_count);
                    EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_INSUFFICIENT_MEM_SIZE);
                    EXPECT_EQUAL(supported_groups_count, 0);
                }

                EXPECT_SUCCESS(s2n_config_get_supported_groups(config, supported_groups, policy_groups_count,
                        &supported_groups_count));
                EXPECT_EQUAL(supported_groups_count, policy_groups_count);
            }
        }

        /* The groups produced by s2n_config_get_supported_groups should match the groups produced
         * by a connection that's configured to send its entire list of supported groups
         */
        for (size_t policy_idx = 0; security_policy_selection[policy_idx].version != NULL; policy_idx++) {
            const struct s2n_security_policy *security_policy = security_policy_selection[policy_idx].security_policy;
            EXPECT_NOT_NULL(security_policy);

            uint32_t expected_groups_count = 0;
            EXPECT_OK(s2n_kem_preferences_groups_available(security_policy->kem_preferences, &expected_groups_count));
            expected_groups_count += security_policy->ecc_preferences->count;

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            config->security_policy = security_policy;

            uint16_t supported_groups[S2N_TEST_MAX_SUPPORTED_GROUPS_COUNT] = { 0 };
            uint16_t supported_groups_count = 0;
            EXPECT_SUCCESS(s2n_config_get_supported_groups(config, supported_groups, s2n_array_len(supported_groups),
                    &supported_groups_count));
            EXPECT_EQUAL(supported_groups_count, expected_groups_count);

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            /* PQ kem groups aren't sent in the supported groups extension before TLS 1.3. */
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer extension_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension_stuffer, 0));
            EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &extension_stuffer));

            uint16_t extension_groups_count = 0;
            EXPECT_OK(s2n_supported_groups_parse_count(&extension_stuffer, &extension_groups_count));
            EXPECT_EQUAL(extension_groups_count, expected_groups_count);

            for (size_t i = 0; i < supported_groups_count; i++) {
                /* s2n_stuffer_read_uint16 is used to read each of the supported groups in
                 * network-order endianness.
                 */
                uint16_t group_iana = 0;
                POSIX_GUARD(s2n_stuffer_read_uint16(&extension_stuffer, &group_iana));

                EXPECT_EQUAL(group_iana, supported_groups[i]);
            }
        }
    }

    /* Test s2n_config_validate_loaded_certificates */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *invalid_cert = NULL, s2n_cert_chain_and_key_ptr_free);
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *valid_cert = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&invalid_cert, "ec", "ecdsa", "p384", "sha256"));
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&valid_cert, "ec", "ecdsa", "p384", "sha384"));

        struct s2n_security_policy rfc9151_applied_locally = security_policy_rfc9151;
        rfc9151_applied_locally.certificate_preferences_apply_locally = true;

        /* rfc9151 doesn't allow SHA256 signatures, but does allow SHA384 signatures, 
         * so ecdsa_p384_sha256 is invalid and ecdsa_p384_sha384 is valid */

        /* valid certs are accepted */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, valid_cert));
            EXPECT_OK(s2n_config_validate_loaded_certificates(config, &rfc9151_applied_locally));
        };

        /* when cert preferences don't apply locally, invalid certs are accepted */
        {
            struct s2n_security_policy non_local_rfc9151 = security_policy_rfc9151;
            non_local_rfc9151.certificate_preferences_apply_locally = false;

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, invalid_cert));
            EXPECT_OK(s2n_config_validate_loaded_certificates(config, &non_local_rfc9151));
        };

        /* Certs in an s2n_config are stored in default_certs_by_type, domain_name_to_cert_map, or
         * both. We want to ensure that the s2n_config_validate_loaded_certificates method will
         * validate certs in both locations.
         */

        /* certs in default_certs_by_type are validated */
        {
            /* s2n_config_set_cert_chain_and_key_defaults populates default_certs_by_type 
             * but doesn't populate domain_name_to_cert_map 
             */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(config, &invalid_cert, 1));

            /* domain certs is empty */
            uint32_t domain_certs_count = 0;
            EXPECT_OK(s2n_map_size(config->domain_name_to_cert_map, &domain_certs_count));
            EXPECT_EQUAL(domain_certs_count, 0);

            /* certs in default_certs_by_type are validated */
            EXPECT_ERROR_WITH_ERRNO(s2n_config_validate_loaded_certificates(config, &rfc9151_applied_locally),
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        };

        /* certs in the domain map are validated */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_build_domain_name_to_cert_map(config, invalid_cert));

            /* default_certs_by_type is empty. */
            EXPECT_EQUAL(s2n_config_get_num_default_certs(config), 0);

            /* certs in domain_map are validated */
            EXPECT_ERROR_WITH_ERRNO(s2n_config_validate_loaded_certificates(config, &rfc9151_applied_locally),
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        };
    };
    END_TEST();
}
