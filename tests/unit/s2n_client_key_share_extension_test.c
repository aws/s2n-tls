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

#include <stdint.h>

#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_security_policies.h"

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_fips.h"

#define S2N_SIZE_OF_CLIENT_SHARE_SIZE   2

#define S2N_PREPARE_DATA_LENGTH( stuffer )   \
    EXPECT_SUCCESS(s2n_stuffer_skip_write(stuffer, S2N_SIZE_OF_CLIENT_SHARE_SIZE))
#define S2N_WRITE_DATA_LENGTH( stuffer )     \
    EXPECT_SUCCESS(s2n_test_rewrite_length(stuffer))

static int s2n_test_rewrite_length(struct s2n_stuffer *stuffer);
static int s2n_write_named_curve(struct s2n_stuffer *out, const struct s2n_ecc_named_curve *existing_curve);
static int s2n_write_key_share(struct s2n_stuffer *out, uint16_t iana_value, uint16_t share_size,
        const struct s2n_ecc_named_curve *existing_curve);

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test that s2n_extensions_key_share_size produces the expected constant result */
    {
        struct s2n_stuffer key_share_extension;
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        int key_share_size;
        EXPECT_SUCCESS(key_share_size = s2n_extensions_client_key_share_size(conn));

        /* should produce the same result if called twice */
        int key_share_size_again;
        EXPECT_SUCCESS(key_share_size_again = s2n_extensions_client_key_share_size(conn));
        EXPECT_EQUAL(key_share_size, key_share_size_again);

        /* should equal the size of the data written on send */
        EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, key_share_size));
        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));
        EXPECT_EQUAL(key_share_size - S2N_EXTENSION_TYPE_FIELD_LENGTH - S2N_EXTENSION_LENGTH_FIELD_LENGTH,
                s2n_stuffer_data_available(&key_share_extension));

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test s2n_client_key_share_extension.send */
    {
        /* Test that s2n_client_key_share_extension.send initializes the client key share list */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];  
                
                if (i == 0) {
                    EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[i]);
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NOT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[i]);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }
            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.send writes a well-formed list of key shares */
        {
            struct s2n_stuffer key_share_extension;
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
        }
        
        /* Test that s2n_client_key_share_extension.send sends empty client key share list when
         * s2n_connection_set_keyshare_by_name_for_testing is called with 'none' */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send an empty list of keyshares */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "none"));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

            /* should contain 0 */
            EXPECT_EQUAL(key_shares_size, 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.send sends client key share list with keyshare present only for curve p-256 */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send only p-256 keyshare in keyshare list */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

            /* should contain only curve p-256 with its sizes */
            uint32_t bytes_processed = 0;
            EXPECT_EQUAL(key_shares_size, s2n_ecc_curve_secp256r1.share_size + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE);

            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            bytes_processed += share_size + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE;

            EXPECT_EQUAL(iana_value, TLS_EC_CURVE_SECP_256_R1);
            EXPECT_EQUAL(share_size, s2n_ecc_curve_secp256r1.share_size);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
            EXPECT_EQUAL(bytes_processed, key_shares_size);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.send sends client key share list with a keyshare present only for curve p-256 and p-384 */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send only p-256 and p-384 keyshares in keyshare list */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp384r1"));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

            /* should contain only curve p-256 and curve p-384 with its sizes */
            uint32_t bytes_processed = 0;
            EXPECT_EQUAL(key_shares_size, s2n_ecc_curve_secp256r1.share_size +  s2n_ecc_curve_secp384r1.share_size
                                              + (2 * (S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE)));

            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            bytes_processed += share_size + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE;

            EXPECT_EQUAL(iana_value, TLS_EC_CURVE_SECP_256_R1);
            EXPECT_EQUAL(share_size, s2n_ecc_curve_secp256r1.share_size);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));

            EXPECT_TRUE(bytes_processed < key_shares_size);

            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            bytes_processed += share_size + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE;

            EXPECT_EQUAL(iana_value, TLS_EC_CURVE_SECP_384_R1);
            EXPECT_EQUAL(share_size,  s2n_ecc_curve_secp384r1.share_size);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));

            EXPECT_EQUAL(bytes_processed, key_shares_size);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test s2n_client_key_share_extension.send for a supported curve present in s2n_all_supported_curves_list,
         * but not present in the ecc_preferences list selected */
        if (s2n_is_evp_apis_supported()) {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(conn->config);
            /* Explicitly set the ecc_preferences list to contain the curves p-256 and p-384 */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(conn->config, "20140601"));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* x25519 is present in s2n_all_supported_curves_list but not in the "default" list */
            const struct s2n_ecc_named_curve *test_curve = &s2n_ecc_curve_x25519;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            for (int i = 0; i < ecc_preferences->count ; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NOT_EQUAL(ecc_evp_params->negotiated_curve, test_curve);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test s2n_client_key_share_extension.send with HelloRetryRequest */
    {
        /* For HelloRetryRequest initiated when a list of empty keyshares are sent in the first ClientHello,
         * test that s2n_client_key_share_extension.send sends a keyshare list containing a single KeyShareEntry
         * for the server selected group/negotiated curve. */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send an empty list of keyshares in ClientHello1 */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "none"));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* ClientHello1 should contain empty keyshare list */
            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                if (ecc_evp_params->negotiated_curve == conn->secure.server_ecc_evp_params.negotiated_curve) {
                    EXPECT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }

            /* Setup the client to have received a HelloRetryRequest */
            EXPECT_MEMCPY_SUCCESS(conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            /* should contain keyshare for only server negotiated curve */
            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                if (ecc_evp_params->negotiated_curve == conn->secure.server_ecc_evp_params.negotiated_curve) {
                    EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }

            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

            /* should contain keyshare for only server negotiated curve */
            uint32_t bytes_processed = 0;
            EXPECT_EQUAL(key_shares_size, conn->secure.server_ecc_evp_params.negotiated_curve->share_size
                                            + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE);

            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            bytes_processed += conn->secure.server_ecc_evp_params.negotiated_curve->share_size + S2N_SIZE_OF_NAMED_GROUP
                            + S2N_SIZE_OF_KEY_SHARE_SIZE;

            EXPECT_EQUAL(iana_value, conn->secure.server_ecc_evp_params.negotiated_curve->iana_id);
            EXPECT_EQUAL(share_size, conn->secure.server_ecc_evp_params.negotiated_curve->share_size);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
            EXPECT_EQUAL(bytes_processed, key_shares_size);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* For HelloRetryRequests when a keyshare does not match, test that s2n_client_key_share_extension.send replaces the list of keyshares,
         * with a list containing a single KeyShareEntry for the server selected group. */
        if (s2n_is_evp_apis_supported()) {
            struct s2n_connection *conn;
            struct s2n_config *config;
            struct s2n_stuffer key_share_extension;

            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            /* Security policy "20190801" contains x25519 */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190801"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            /* Force the client to send only p-256 and p-384 keyshares in keyshare list */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp384r1"));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            /* Verify that only p-256 and p-384 keyshares are sent */
            for (size_t i = 0; i < ecc_preferences->count; i++) {
                if (ecc_preferences->ecc_curves[i]->iana_id == TLS_EC_CURVE_SECP_256_R1
                    || ecc_preferences->ecc_curves[i]->iana_id == TLS_EC_CURVE_SECP_384_R1) {
                    EXPECT_NOT_NULL(conn->secure.client_ecc_evp_params[i].negotiated_curve);
                    EXPECT_NOT_NULL(conn->secure.client_ecc_evp_params[i].evp_pkey);
                } else {
                    EXPECT_NULL(conn->secure.client_ecc_evp_params[i].negotiated_curve);
                    EXPECT_NULL(conn->secure.client_ecc_evp_params[i].evp_pkey);
                }
            }

            /* Setup the client to have received a HelloRetryRequest with server negotiated curve as x25519 */
            EXPECT_MEMCPY_SUCCESS(conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
            conn->secure.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_x25519;

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            /* should contain keyshare for only server negotiated curve */
            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                if (ecc_evp_params->negotiated_curve == conn->secure.server_ecc_evp_params.negotiated_curve) {
                    EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }

            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

            /* should contain keyshare for only server negotiated curve */
            uint32_t bytes_processed = 0;
            EXPECT_EQUAL(key_shares_size, conn->secure.server_ecc_evp_params.negotiated_curve->share_size
                                            + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE);

            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            bytes_processed += conn->secure.server_ecc_evp_params.negotiated_curve->share_size + S2N_SIZE_OF_NAMED_GROUP
                            + S2N_SIZE_OF_KEY_SHARE_SIZE;

            EXPECT_EQUAL(iana_value, conn->secure.server_ecc_evp_params.negotiated_curve->iana_id);
            EXPECT_EQUAL(share_size, conn->secure.server_ecc_evp_params.negotiated_curve->share_size);
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
            struct s2n_stuffer key_share_extension;

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* Setup the client to have received a HelloRetryRequest */
            memcpy_check(client_conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn));
            client_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];

            /* During HRR, A key_share list with a single key_share entry,
            * corresponding to the server negotiated curve is sent by the client */
            EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));

            /* should contain keyshare for only server negotiated curve */
            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &client_conn->secure.client_ecc_evp_params[i];
                if (ecc_evp_params->negotiated_curve == client_conn->secure.server_ecc_evp_params.negotiated_curve) {
                    EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }


            server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* Verify that a keyshare list with a single keyshare corresponding to the server negotiated curve is received */
            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &server_conn->secure.client_ecc_evp_params[i];
                if (ecc_evp_params->negotiated_curve == server_conn->secure.server_ecc_evp_params.negotiated_curve) {
                    EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* For HelloRetryRequests, test that s2n_client_key_share_extension.send fails,
         * if the server negotiated_curve is not set and is NULL. */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            /* Setup the client to have received a HelloRetryRequest */
            EXPECT_MEMCPY_SUCCESS(conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
            conn->secure.server_ecc_evp_params.negotiated_curve = NULL;

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_key_share_extension.send(conn, &key_share_extension),
                                      S2N_ERR_BAD_KEY_SHARE);

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test s2n_client_key_share_extension.recv */
    {
        /* Test that s2n_client_key_share_extension.recv is a no-op
         * if tls1.3 not enabled AND in use  */
        {
            struct s2n_connection *client_conn, *server_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            DEFER_CLEANUP(struct s2n_stuffer key_share_extension, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));
            uint16_t key_share_extension_size = s2n_stuffer_data_available(&key_share_extension);

            EXPECT_SUCCESS(s2n_disable_tls13());
            server_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_share_extension_size);

            EXPECT_SUCCESS(s2n_disable_tls13());
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_share_extension_size);

            EXPECT_SUCCESS(s2n_enable_tls13());
            server_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_share_extension_size);

            EXPECT_SUCCESS(s2n_enable_tls13());
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test that s2n_client_key_share_extension.recv can read and parse
         * the result of s2n_client_key_share_extension.send */
        {
            struct s2n_connection *client_conn, *server_conn;
            struct s2n_stuffer key_share_extension;

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));
            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should set internal state the same as the client */
            struct s2n_ecc_evp_params *server_ecc_evp_params;
            struct s2n_ecc_evp_params *client_ecc_evp_params;
            for (size_t i = 0; i < ecc_pref->count; i++) {
                server_ecc_evp_params = &server_conn->secure.client_ecc_evp_params[i];
                client_ecc_evp_params = &client_conn->secure.client_ecc_evp_params[i];

                if (i == 0) {
                    EXPECT_NOT_NULL(server_ecc_evp_params->negotiated_curve);
                    EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
                    EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, client_ecc_evp_params));
                } else {
                    EXPECT_NULL(server_ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(server_ecc_evp_params->evp_pkey);
                }
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test that s2n_client_key_share_extension.recv errors on client shares size larger
         * than available data */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, ecc_pref->ecc_curves[0]->share_size * 10));
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, ecc_pref->ecc_curves[0]));

            EXPECT_FAILURE(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.recv errors on key share size longer than data */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
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
        }

        /* Test that s2n_client_key_share_extension.recv accepts a subset of supported curves */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
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
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[0];
            EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
            EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_pref->ecc_curves[0]);

            /* should not have initialized any other curves */
            for (int i = 1; i < ecc_pref->count; i++) {
                ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.recv handles empty client share list */
        {
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            /* should not have initialized any curves */
            for (size_t i = 0; i < ecc_pref->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &server_conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test that s2n_client_key_share_extension.recv ignores unsupported curves */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
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
            for (int i = 0; i < ecc_pref->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.recv ignores curves with incorrect key size */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
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
            for (int i = 0; i < ecc_pref->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.recv uses first instance of duplicate curves */
        {
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension;
            struct s2n_ecc_evp_params first_params, second_params;
            int supported_curve_index = 0;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
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
                &server_conn->secure.client_ecc_evp_params[supported_curve_index], &first_params));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&first_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&second_params));
        }

        /* Test that s2n_client_key_share_extension.recv ignores points that can't be parsed */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            /* Write first curve */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, ecc_pref->ecc_curves[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            /* Mess up point by erasing most of it */
            int data_size = s2n_stuffer_data_available(&key_share_extension);
            GUARD(s2n_stuffer_wipe_n(&key_share_extension, data_size / 2));
            GUARD(s2n_stuffer_skip_write(&key_share_extension, data_size / 2));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            for (int i = 1; i < ecc_pref->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.recv ignores a supported curve present in
         * s2n_all_supported_curves_list but not in s2n_ecc_preferences list selected
         */
        {
            if (s2n_is_evp_apis_supported()) {
                struct s2n_connection *conn;
                struct s2n_stuffer key_share_extension;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
                EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));
                EXPECT_NOT_NULL(conn->config);
                /* Explicitly set the ecc_preferences list to contain the curves p-256 and p-384 */
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(conn->config, "20140601"));

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
                for (int i = 0; i < ecc_pref->count; i++) {
                    struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                    EXPECT_NULL(ecc_evp_params->negotiated_curve);
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }

                EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }
    }

#if !defined(S2N_NO_PQ)
    /* PQ hybrid tests for s2n_client_key_share_extension */
    {
        const struct s2n_kem_group *all_kem_groups[] = {
            &s2n_secp256r1_sike_p434_r2,
            &s2n_secp256r1_bike1_l1_r2,
            &s2n_secp256r1_kyber_512_r2,
#if EVP_APIS_SUPPORTED
            &s2n_x25519_sike_p434_r2,
            &s2n_x25519_bike1_l1_r2,
            &s2n_x25519_kyber_512_r2,
#endif
        };

        EXPECT_EQUAL(S2N_SUPPORTED_KEM_GROUPS_COUNT, s2n_array_len(all_kem_groups));

        if (s2n_is_in_fips_mode()) {
            /* Test that s2n_client_key_share_extension.send sends only ECC key shares when in FIPS mode */
            const struct s2n_kem_preferences test_kem_prefs = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(all_kem_groups),
                .tls13_kem_groups = all_kem_groups,
            };

            const struct s2n_security_policy test_security_policy = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
            };

            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->security_policy_override = &test_security_policy;

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref->tls13_kem_group_count, S2N_SUPPORTED_KEM_GROUPS_COUNT);

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 1024));
            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            /* Assert total key shares extension size is correct */
            uint16_t sent_key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_key_shares_size));
            EXPECT_EQUAL(sent_key_shares_size, s2n_stuffer_data_available(&key_share_extension));

            /* ECC key shares should have the format: IANA ID || size || share. Only one ECC key share
             * should be sent (as per defualt s2n behavior). */
            uint16_t iana_value, share_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
            EXPECT_EQUAL(iana_value, ecc_preferences->ecc_curves[0]->iana_id);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
            EXPECT_EQUAL(share_size, ecc_preferences->ecc_curves[0]->share_size);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));

            /* If all the sizes/bytes were correctly written, there should be nothing left over */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        } else {
            /* Test that s2n_client_key_share_extension.send generates and sends PQ hybrid and ECC shares correctly
             * when not in FIPS mode. */
            for (size_t i = 0; i < S2N_SUPPORTED_KEM_GROUPS_COUNT; i++) {
                /* The PQ hybrid key share send function only sends the highest priority PQ key share. On each
                 * iteration of the outer loop of this test (index i), we populate test_kem_groups[] with a
                 * different permutation of all_kem_groups[] to ensure we handle each kem_group key share
                 * correctly. */
                const struct s2n_kem_group *test_kem_groups[S2N_SUPPORTED_KEM_GROUPS_COUNT];
                for (size_t j = 0; j < S2N_SUPPORTED_KEM_GROUPS_COUNT; j++) {
                    test_kem_groups[j] = all_kem_groups[(j + i) % S2N_SUPPORTED_KEM_GROUPS_COUNT];
                }

                const struct s2n_kem_preferences test_kem_prefs = {
                    .kem_count = 0,
                    .kems = NULL,
                    .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                    .tls13_kem_groups = test_kem_groups,
                };

                const struct s2n_security_policy test_security_policy = {
                    .minimum_protocol_version = S2N_SSLv3,
                    .cipher_preferences = &cipher_preferences_test_all_tls13,
                    .kem_preferences = &test_kem_prefs,
                    .signature_preferences = &s2n_signature_preferences_20200207,
                    .ecc_preferences = &s2n_ecc_preferences_20200310,
                };

                struct s2n_stuffer key_share_extension;
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                conn->security_policy_override = &test_security_policy;

                const struct s2n_ecc_preferences *ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
                EXPECT_NOT_NULL(ecc_pref);

                const struct s2n_kem_preferences *kem_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
                EXPECT_NOT_NULL(kem_pref);
                EXPECT_EQUAL(kem_pref->tls13_kem_group_count, S2N_SUPPORTED_KEM_GROUPS_COUNT);
                EXPECT_EQUAL(test_kem_groups[0], kem_pref->tls13_kem_groups[0]);
                const struct s2n_kem_group *test_kem_group = kem_pref->tls13_kem_groups[0];

                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 4096));
                EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

                /* First, assert that the client saved its private keys correctly in the connection state
                 * for both hybrid PQ and classic ECC */
                struct s2n_kem_group_params *kem_group_params = &conn->secure.client_kem_group_params[0];
                EXPECT_EQUAL(kem_group_params->kem_group, test_kem_group);
                EXPECT_EQUAL(kem_group_params->kem_params.kem, test_kem_group->kem);
                EXPECT_NOT_NULL(kem_group_params->kem_params.private_key.data);
                EXPECT_EQUAL(kem_group_params->kem_params.private_key.size, test_kem_group->kem->private_key_length);
                EXPECT_EQUAL(kem_group_params->ecc_params.negotiated_curve, test_kem_group->curve);
                EXPECT_NOT_NULL(kem_group_params->ecc_params.evp_pkey);

                struct s2n_ecc_evp_params *ecc_params = &conn->secure.client_ecc_evp_params[0];
                EXPECT_EQUAL(ecc_params->negotiated_curve, ecc_pref->ecc_curves[0]);
                EXPECT_NOT_NULL(ecc_params->evp_pkey);

                /* Next, assert that the client didn't generate/save any hybrid or ECC params that it shouldn't have */
                for (size_t kem_group_index = 1; kem_group_index < S2N_SUPPORTED_KEM_GROUPS_COUNT; kem_group_index++) {
                    EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_group);
                    EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_params.kem);
                    EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.data);
                    EXPECT_EQUAL(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.size, 0);
                    EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].ecc_params.negotiated_curve);
                    EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].ecc_params.evp_pkey);
                }
                for (size_t ecc_index = 1; ecc_index < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; ecc_index++) {
                    EXPECT_NULL(conn->secure.client_ecc_evp_params[ecc_index].negotiated_curve);
                    EXPECT_NULL(conn->secure.client_ecc_evp_params[ecc_index].evp_pkey);
                }

                /* Now, assert that the client sent the correct bytes over the wire for the key share extension */
                /* Assert total key shares extension size is correct */
                uint16_t sent_key_shares_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_key_shares_size));
                EXPECT_EQUAL(sent_key_shares_size, s2n_stuffer_data_available(&key_share_extension));

                /* Assert that the hybrid key share is correct:
                 * IANA ID || total hybrid share size || ECC share size || ECC share || PQ share size || PQ share */
                uint16_t sent_hybrid_iana_id;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_iana_id));
                EXPECT_EQUAL(sent_hybrid_iana_id, kem_pref->tls13_kem_groups[0]->iana_id);

                uint16_t expected_hybrid_share_size =
                          S2N_SIZE_OF_KEY_SHARE_SIZE
                        + test_kem_group->curve->share_size
                        + S2N_SIZE_OF_KEY_SHARE_SIZE
                        + test_kem_group->kem->public_key_length;
                uint16_t sent_hybrid_share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_share_size));
                EXPECT_EQUAL(sent_hybrid_share_size, expected_hybrid_share_size);

                uint16_t hybrid_ecc_share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_ecc_share_size));
                EXPECT_EQUAL(hybrid_ecc_share_size, test_kem_group->curve->share_size);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, hybrid_ecc_share_size));

                uint16_t hybrid_pq_share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_pq_share_size));
                EXPECT_EQUAL(hybrid_pq_share_size, test_kem_group->kem->public_key_length);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, hybrid_pq_share_size));

                /* Assert that the ECC key share is correct: IANA ID || size || share */
                uint16_t ecc_iana_value, ecc_share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &ecc_iana_value));
                EXPECT_EQUAL(ecc_iana_value, ecc_pref->ecc_curves[0]->iana_id);
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &ecc_share_size));
                EXPECT_EQUAL(ecc_share_size, ecc_pref->ecc_curves[0]->share_size);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, ecc_share_size));

                /* If all the sizes/bytes were correctly written, there should be nothing left over */
                EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }
    }
#endif

    END_TEST();
    return 0;
}

static int s2n_test_rewrite_length(struct s2n_stuffer *stuffer)
{
    notnull_check(stuffer);

    int length = s2n_stuffer_data_available(stuffer) - S2N_SIZE_OF_CLIENT_SHARE_SIZE;
    GUARD(s2n_stuffer_rewrite(stuffer));
    GUARD(s2n_stuffer_write_uint16(stuffer, length));
    GUARD(s2n_stuffer_skip_write(stuffer, length));
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
    notnull_check(out);
    notnull_check(existing_curve);

    struct s2n_ecc_evp_params ecc_evp_params;
    const struct s2n_ecc_named_curve test_curve = {
            .iana_id = iana_value,
            .libcrypto_nid = existing_curve->libcrypto_nid,
            .name = existing_curve->name,
            .share_size = share_size
    };

    ecc_evp_params.negotiated_curve = &test_curve;
    ecc_evp_params.evp_pkey = NULL;
    if (s2n_ecdhe_parameters_send(&ecc_evp_params, out) < 0) {
        GUARD(s2n_ecc_evp_params_free(&ecc_evp_params));
        return 1; 
    }

    GUARD(s2n_ecc_evp_params_free(&ecc_evp_params));
    return 0;
}
