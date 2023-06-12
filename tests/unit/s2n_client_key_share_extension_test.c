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

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

#define HELLO_RETRY_MSG_NO 1

#define S2N_SIZE_OF_CLIENT_SHARE_SIZE 2

#define S2N_PREPARE_DATA_LENGTH(stuffer) \
    EXPECT_SUCCESS(s2n_stuffer_skip_write(stuffer, S2N_SIZE_OF_CLIENT_SHARE_SIZE))
#define S2N_WRITE_DATA_LENGTH(stuffer) \
    EXPECT_SUCCESS(s2n_test_rewrite_length(stuffer))

static int s2n_test_rewrite_length(struct s2n_stuffer *stuffer);
static int s2n_write_named_curve(struct s2n_stuffer *out, const struct s2n_ecc_named_curve *existing_curve);
static int s2n_write_key_share(struct s2n_stuffer *out, uint16_t iana_value, uint16_t share_size,
        const struct s2n_ecc_named_curve *existing_curve);

S2N_RESULT s2n_extensions_client_key_share_size(struct s2n_connection *conn, uint32_t *size)
{
    RESULT_ENSURE_REF(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    RESULT_ENSURE_REF(ecc_pref);

    uint32_t s2n_client_key_share_extension_size = S2N_SIZE_OF_EXTENSION_TYPE
            + S2N_SIZE_OF_EXTENSION_DATA_SIZE
            + S2N_SIZE_OF_CLIENT_SHARES_SIZE;

    s2n_client_key_share_extension_size += S2N_SIZE_OF_KEY_SHARE_SIZE + S2N_SIZE_OF_NAMED_GROUP;
    s2n_client_key_share_extension_size += ecc_pref->ecc_curves[0]->share_size;

    *size = s2n_client_key_share_extension_size;

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test that s2n_extensions_key_share_size produces the expected constant result */
    {
        struct s2n_stuffer key_share_extension = { 0 };
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        uint32_t key_share_size = 0;
        EXPECT_OK(s2n_extensions_client_key_share_size(conn, &key_share_size));

        /* should produce the same result if called twice */
        uint32_t key_share_size_again = 0;
        EXPECT_OK(s2n_extensions_client_key_share_size(conn, &key_share_size_again));
        EXPECT_EQUAL(key_share_size, key_share_size_again);

        /* should equal the size of the data written on send */
        EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, key_share_size));
        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));
        EXPECT_EQUAL(key_share_size - S2N_EXTENSION_TYPE_FIELD_LENGTH - S2N_EXTENSION_LENGTH_FIELD_LENGTH,
                s2n_stuffer_data_available(&key_share_extension));

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_client_key_share_extension.send */
    {
        /* Test that s2n_client_key_share_extension.send initializes the client key share list */
        {
            struct s2n_stuffer key_share_extension = { 0 };
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[0]);
            EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that s2n_client_key_share_extension.send writes a well-formed list of key shares */
        {
            struct s2n_stuffer key_share_extension = { 0 };
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));
            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            /* should have correct shares size */
            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            uint16_t actual_key_shares_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_EQUAL(key_shares_size, actual_key_shares_size);
            EXPECT_EQUAL(key_shares_size, s2n_stuffer_data_available(&key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* should contain only the default supported curve */
            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_EQUAL(iana_value, ecc_preferences->ecc_curves[0]->iana_id);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            EXPECT_EQUAL(share_size, ecc_preferences->ecc_curves[0]->share_size);

            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test s2n_client_key_share_extension.send for a supported curve present in s2n_all_supported_curves_list,
         * but not present in the ecc_preferences list selected */
        if (s2n_is_evp_apis_supported()) {
            struct s2n_stuffer key_share_extension = { 0 };
            struct s2n_connection *conn;
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            /* Explicitly set the ecc_preferences list to contain the curves p-256 and p-384 */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20140601"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* x25519 is present in s2n_all_supported_curves_list but not in the "default" list */
            const struct s2n_ecc_named_curve *test_curve = &s2n_ecc_curve_x25519;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_NOT_EQUAL(ecc_evp_params->negotiated_curve, test_curve);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    };

    /* Test s2n_client_key_share_extension.send with HelloRetryRequest */
    {
        /**
         * For HelloRetryRequests when a keyshare does not match, test that s2n_client_key_share_extension.send replaces
         * the list of keyshares with a list containing a single KeyShareEntry for the server selected group.
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.1.2
         *= type=test
         *# -   If a "key_share" extension was supplied in the HelloRetryRequest,
         *#     replacing the list of shares with a list containing a single
         *#     KeyShareEntry from the indicated group.
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.2.8
         *= type=test
         *# Otherwise, when sending the new ClientHello, the client MUST
         *# replace the original "key_share" extension with one containing only a
         *# new KeyShareEntry for the group indicated in the selected_group field
         *# of the triggering HelloRetryRequest.
         **/
        if (s2n_is_evp_apis_supported()) {
            struct s2n_connection *conn;
            struct s2n_config *config;
            struct s2n_stuffer key_share_extension = { 0 };

            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            /* Security policy "20190801" contains x25519 */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190801"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            /* Force the client to send an unsupported curve in keyshare list */
            conn->security_policy_override = &security_policy_test_tls13_retry;

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            /* Setup the client to have received a HelloRetryRequest with server negotiated curve as x25519 */
            EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
            conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_x25519;

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

            /* should contain keyshare for only server negotiated curve */
            uint32_t bytes_processed = 0;
            EXPECT_EQUAL(key_shares_size, conn->kex_params.server_ecc_evp_params.negotiated_curve->share_size + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE);

            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            bytes_processed += conn->kex_params.server_ecc_evp_params.negotiated_curve->share_size + S2N_SIZE_OF_NAMED_GROUP
                    + S2N_SIZE_OF_KEY_SHARE_SIZE;

            EXPECT_EQUAL(iana_value, conn->kex_params.server_ecc_evp_params.negotiated_curve->iana_id);
            EXPECT_EQUAL(share_size, conn->kex_params.server_ecc_evp_params.negotiated_curve->share_size);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
            EXPECT_EQUAL(bytes_processed, key_shares_size);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* For HelloRetryRequests, test that s2n_client_key_share_extension.recv can read and parse
         * the result of s2n_client_key_share_extension.send */
        {
            struct s2n_connection *client_conn;
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension = { 0 };

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* Setup the client to have received a HelloRetryRequest */
            POSIX_CHECKED_MEMCPY(client_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn));
            client_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];

            /* During HRR, A key_share list with a single key_share entry,
            * corresponding to the server negotiated curve is sent by the client */
            EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));

            /* should contain keyshare for only server negotiated curve */
            struct s2n_ecc_evp_params *client_ecc_evp_params = &client_conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(client_ecc_evp_params->negotiated_curve, client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_NOT_NULL(client_ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(client_ecc_evp_params->evp_pkey);

            server_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Verify that a keyshare list with a single keyshare corresponding to the server negotiated curve is received */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(server_ecc_evp_params->negotiated_curve, server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_NOT_NULL(server_ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* For HelloRetryRequests, test that s2n_client_key_share_extension.send fails,
         * if the server negotiated_curve is not set and is NULL. */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            /* Setup the client to have received a HelloRetryRequest */
            EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
            conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;
            conn->kex_params.server_kem_group_params.kem_group = NULL;

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_key_share_extension.send(conn, &key_share_extension),
                    S2N_ERR_BAD_KEY_SHARE);

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* For HelloRetryRequests, verify that we cannot resend an existing share. */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            const struct s2n_ecc_named_curve *curve = ecc_preferences->ecc_curves[0];

            struct s2n_stuffer first_extension = { 0 }, second_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&first_extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&second_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &first_extension));
            EXPECT_EQUAL(conn->kex_params.client_ecc_evp_params.negotiated_curve, curve);
            EXPECT_NOT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);

            /* Setup the client to have received a HelloRetryRequest */
            EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
            conn->early_data_state = S2N_EARLY_DATA_REJECTED;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = curve;

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_key_share_extension.send(conn, &second_extension),
                    S2N_ERR_BAD_KEY_SHARE);

            EXPECT_SUCCESS(s2n_stuffer_free(&first_extension));
            EXPECT_SUCCESS(s2n_stuffer_free(&second_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_client_key_share_extension.recv */
    {
        /* Test that s2n_client_key_share_extension.recv is a no-op
         * if not using TLS1.3 */
        {
            struct s2n_connection *client_conn, *server_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            DEFER_CLEANUP(struct s2n_stuffer key_share_extension, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));
            uint16_t key_share_extension_size = s2n_stuffer_data_available(&key_share_extension);

            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            server_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_recv(&s2n_client_key_share_extension, server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_share_extension_size);

            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv can read and parse
         * the result of s2n_client_key_share_extension.send */
        {
            struct s2n_connection *client_conn, *server_conn;
            struct s2n_stuffer key_share_extension = { 0 };

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should set internal state the same as the client */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            struct s2n_ecc_evp_params *client_ecc_evp_params = &client_conn->kex_params.client_ecc_evp_params;
            EXPECT_NOT_NULL(server_ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv can handle an empty keyshare list */
        {
            /* Just the uint16_t length as "0" */
            uint8_t empty_keyshare_extension[] = { 0x00, 0x00 };

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, sizeof(empty_keyshare_extension)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&key_share_extension, empty_keyshare_extension, sizeof(empty_keyshare_extension)));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Triggers retry */
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv can handle a keyshare for
         * a supported curve that isn't its first choice curve. */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params = { .negotiated_curve = ecc_pref->ecc_curves[1] };

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params, &key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Does not trigger retries */
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            /* Expected share present */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_NOT_NULL(server_ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, &client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv can handle multiple keyshares */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params[] = {
                { .negotiated_curve = ecc_pref->ecc_curves[0] },
                { .negotiated_curve = ecc_pref->ecc_curves[1] }
            };

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[0], &key_share_extension));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[1], &key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Does not trigger retries */
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            /* Highest priority share (0) present */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_NOT_NULL(server_ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, &client_ecc_evp_params[0]));

            for (size_t i = 0; i < s2n_array_len(client_ecc_evp_params); i++) {
                EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params[i]));
            }
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv selects the highest priority share,
         * even if it appears last in the client's list of shares. */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params[] = {
                { .negotiated_curve = ecc_pref->ecc_curves[0] },
                { .negotiated_curve = ecc_pref->ecc_curves[1] }
            };

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[1], &key_share_extension));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[1], &key_share_extension));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[0], &key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Does not trigger retries */
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            /* Highest priority curve (0) share present */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(server_ecc_evp_params->negotiated_curve, ecc_pref->ecc_curves[0]);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, &client_ecc_evp_params[0]));

            for (size_t i = 0; i < s2n_array_len(client_ecc_evp_params); i++) {
                EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params[i]));
            }
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv ignores shares for curves not offered
         * by the client / "mutually supported", and triggers a retry instead.
         */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;

            /* Do NOT mark curve 0 as mutually supported */
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
            server_conn->kex_params.mutually_supported_curves[0] = NULL;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params = { .negotiated_curve = ecc_pref->ecc_curves[0] };

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params, &key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Client key share ignored, so retry triggered */
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            /* No valid client key share present */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(server_ecc_evp_params->negotiated_curve);
            EXPECT_NULL(server_ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv ignores shares for curves not offered
         * by the client / "mutually supported", and chooses a lower priority curve instead.
         */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;

            /* Do NOT mark curve 0 as mutually supported */
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
            server_conn->kex_params.mutually_supported_curves[0] = NULL;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params[] = {
                { .negotiated_curve = ecc_pref->ecc_curves[0] },
                { .negotiated_curve = ecc_pref->ecc_curves[1] }
            };

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[0], &key_share_extension));
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[1], &key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Does not trigger a retry */
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            /* Second highest priority curve (1) share present, because highest priority not "mutually supported" */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(server_ecc_evp_params->negotiated_curve, ecc_pref->ecc_curves[1]);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, &client_ecc_evp_params[1]));

            for (size_t i = 0; i < s2n_array_len(client_ecc_evp_params); i++) {
                EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params[i]));
            }
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv errors on client shares size larger
         * than available data */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, ecc_pref->ecc_curves[0]->share_size * 10));
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, ecc_pref->ecc_curves[0]));

            EXPECT_FAILURE(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that s2n_client_key_share_extension.recv errors on key share size longer than data */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* Write curve with huge length */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    ecc_pref->ecc_curves[0]->iana_id, ecc_pref->ecc_curves[0]->share_size * 10, ecc_pref->ecc_curves[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_FAILURE(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that s2n_client_key_share_extension.recv accepts a subset of supported curves */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* Write only first curve */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, ecc_pref->ecc_curves[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should have initialized first curve */
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
            EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_pref->ecc_curves[0]);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that s2n_client_key_share_extension.recv handles empty client share list */
        {
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            /* should not have initialized any curves */
            struct s2n_ecc_evp_params *ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv ignores unsupported curves */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            S2N_PREPARE_DATA_LENGTH(&key_share_extension);

            /* Write unsupported curves */
            /* 0 -> unallocated_RESERVED */
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    0, ecc_pref->ecc_curves[0]->share_size, ecc_pref->ecc_curves[0]));
            /* 0xFF01 -> obsolete_RESERVED */
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    65281, ecc_pref->ecc_curves[0]->share_size, ecc_pref->ecc_curves[0]));

            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that s2n_client_key_share_extension.recv ignores curves with incorrect key size */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* Write supported curve, but with a different curve's size */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    ecc_pref->ecc_curves[0]->iana_id, ecc_pref->ecc_curves[1]->share_size, ecc_pref->ecc_curves[1]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that s2n_client_key_share_extension.recv uses first instance of duplicate curves */
        {
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension = { 0 };
            struct s2n_ecc_evp_params first_params, second_params;
            int supported_curve_index = 0;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            S2N_PREPARE_DATA_LENGTH(&key_share_extension);

            /* Write first curve once */
            first_params.negotiated_curve = ecc_pref->ecc_curves[supported_curve_index];
            first_params.evp_pkey = NULL;
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&first_params, &key_share_extension));

            /* Write first curve again */
            second_params.negotiated_curve = ecc_pref->ecc_curves[supported_curve_index];
            second_params.evp_pkey = NULL;
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&second_params, &key_share_extension));

            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should have only copied the first set of params */
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(
                    &server_conn->kex_params.client_ecc_evp_params, &first_params));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&first_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&second_params));
        };

        /* Test that s2n_client_key_share_extension.recv ignores ECDHE points that can't be parsed */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension = { 0 };
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            /* Explicitly set the ecc_preferences list to only contain the curves p-256 and p-384 */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20140601"));

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* Write first curve */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, ecc_pref->ecc_curves[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            /* Mess up point by erasing most of it */
            int data_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&key_share_extension, data_size / 2));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_share_extension, data_size / 2));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test that s2n_client_key_share_extension.recv ignores ECDHE points that can't be parsed,
         * and continues to parse valid key shares afterwards. */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            /* Explicitly set the ecc_preferences list to only contain the curves p-256 and p-384 */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20140601"));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params[] = {
                { .negotiated_curve = ecc_pref->ecc_curves[0] },
                { .negotiated_curve = ecc_pref->ecc_curves[1] }
            };

            /* Write share list length */
            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            /* Write first share. Mess up point by erasing most of it */
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[0], &key_share_extension));
            int data_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&key_share_extension, data_size / 2));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_share_extension, data_size / 2));
            /* Write second, valid share */
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[1], &key_share_extension));
            /* Finish share list length */
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Should have chosen curve 1, because curve 0 was malformed */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(server_ecc_evp_params->negotiated_curve, ecc_pref->ecc_curves[1]);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, &client_ecc_evp_params[1]));

            for (size_t i = 0; i < s2n_array_len(client_ecc_evp_params); i++) {
                EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params[i]));
            }
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test that s2n_client_key_share_extension.recv ignores ECDHE points that can't be parsed,
         * and doesn't ignore / forget / overwrite valid key shares already parsed. */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
            EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

            struct s2n_stuffer key_share_extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            EXPECT_TRUE(ecc_pref->count >= 2);

            struct s2n_ecc_evp_params client_ecc_evp_params[] = {
                { .negotiated_curve = ecc_pref->ecc_curves[0] },
                { .negotiated_curve = ecc_pref->ecc_curves[1] }
            };

            /* Write share list length */
            struct s2n_stuffer_reservation keyshare_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
            /* Write first, valid share */
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[0], &key_share_extension));
            /* Write second share. Mess up point by erasing most of it */
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&client_ecc_evp_params[1], &key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&key_share_extension, ecc_pref->ecc_curves[1]->share_size / 2));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_share_extension, ecc_pref->ecc_curves[1]->share_size / 2));
            /* Finish share list length */
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Should have chosen highest priority key share (0) */
            struct s2n_ecc_evp_params *server_ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_EQUAL(server_ecc_evp_params->negotiated_curve, ecc_pref->ecc_curves[0]);
            EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
            EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, &client_ecc_evp_params[0]));

            for (size_t i = 0; i < s2n_array_len(client_ecc_evp_params); i++) {
                EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_ecc_evp_params[i]));
            }
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test that s2n_client_key_share_extension.recv ignores a supported curve present in
         * s2n_all_supported_curves_list but not in s2n_ecc_preferences list selected
         */
        {
            if (s2n_is_evp_apis_supported()) {
                struct s2n_connection *conn;
                struct s2n_stuffer key_share_extension = { 0 };
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
                EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
                EXPECT_OK(s2n_set_all_mutually_supported_groups(conn));
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

                /* Explicitly set the ecc_preferences list to contain the curves p-256 and p-384 */
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20140601"));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

                const struct s2n_ecc_preferences *ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
                EXPECT_NOT_NULL(ecc_pref);

                /* x25519 is present in s2n_all_supported_curves_list but not in the "default" list */
                const struct s2n_ecc_named_curve *test_curve = &s2n_ecc_curve_x25519;

                S2N_PREPARE_DATA_LENGTH(&key_share_extension);

                EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                        test_curve->iana_id, test_curve->share_size, test_curve));

                S2N_WRITE_DATA_LENGTH(&key_share_extension);

                EXPECT_SUCCESS(s2n_client_key_share_extension.recv(conn, &key_share_extension));

                /* should read all data */
                EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                /* should not have initialized any curves */
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->kex_params.client_ecc_evp_params;
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);

                EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_config_free(config));
            }
        };
    };

    END_TEST();
    return 0;
}

static int s2n_test_rewrite_length(struct s2n_stuffer *stuffer)
{
    POSIX_ENSURE_REF(stuffer);

    int length = s2n_stuffer_data_available(stuffer) - S2N_SIZE_OF_CLIENT_SHARE_SIZE;
    POSIX_GUARD(s2n_stuffer_rewrite(stuffer));
    POSIX_GUARD(s2n_stuffer_write_uint16(stuffer, length));
    POSIX_GUARD(s2n_stuffer_skip_write(stuffer, length));
    return 0;
}

static int s2n_write_named_curve(struct s2n_stuffer *out,
        const struct s2n_ecc_named_curve *existing_curve)
{
    return s2n_write_key_share(out, existing_curve->iana_id, existing_curve->share_size, existing_curve);
}

static int s2n_write_key_share(struct s2n_stuffer *out,
        uint16_t iana_value, uint16_t share_size,
        const struct s2n_ecc_named_curve *existing_curve)
{
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(existing_curve);

    struct s2n_ecc_evp_params ecc_evp_params;
    const struct s2n_ecc_named_curve test_curve = {
        .iana_id = iana_value,
        .libcrypto_nid = existing_curve->libcrypto_nid,
        .name = existing_curve->name,
        .share_size = share_size,
        .generate_key = existing_curve->generate_key
    };

    ecc_evp_params.negotiated_curve = &test_curve;
    ecc_evp_params.evp_pkey = NULL;
    if (s2n_ecdhe_parameters_send(&ecc_evp_params, out) < 0) {
        POSIX_GUARD(s2n_ecc_evp_params_free(&ecc_evp_params));
        return 1;
    }

    POSIX_GUARD(s2n_ecc_evp_params_free(&ecc_evp_params));
    return 0;
}
