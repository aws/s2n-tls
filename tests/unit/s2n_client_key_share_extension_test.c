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

            for (int i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[i]);
                EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
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

            /* should contain every supported curve, in order, with their sizes */
            for (int i = 0; i < ecc_preferences->count; i++) {
                uint16_t iana_value, share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
                EXPECT_EQUAL(iana_value, ecc_preferences->ecc_curves[i]->iana_id);
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
                EXPECT_EQUAL(share_size, ecc_preferences->ecc_curves[i]->share_size);

                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
        
        /* Test that s2n_client_key_share_extension.send sends empty client key share list when
         * s2n_connection_set_keyshare_by_group_for_testing is called with IANA_ID = 0 */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send an empty list of keyshares */
            uint16_t iana_value = 0;
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_group_for_testing(conn, iana_value));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[i]);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.send sends client key share list with keyshare present only for curve p-256 */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send only p-256 keyshare in keyshare list */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_group_for_testing(conn, TLS_EC_CURVE_SECP_256_R1));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[i]);
                if (ecc_evp_params->negotiated_curve->iana_id == TLS_EC_CURVE_SECP_256_R1) {
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_client_key_share_extension.send sends client key share list with a keyshare present only for curve p-256 and p-384 */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Force the client to send only p-256  and p-384 keyshares in keyshare list */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_group_for_testing(conn, TLS_EC_CURVE_SECP_256_R1));
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_group_for_testing(conn, TLS_EC_CURVE_SECP_384_R1));

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            for (size_t i = 0; i < ecc_preferences->count; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_EQUAL(ecc_evp_params->negotiated_curve, ecc_preferences->ecc_curves[i]);
                if (ecc_evp_params->negotiated_curve->iana_id == TLS_EC_CURVE_SECP_256_R1 || 
                     ecc_evp_params->negotiated_curve->iana_id == TLS_EC_CURVE_SECP_384_R1) {
                    EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
                } else {
                    EXPECT_NULL(ecc_evp_params->evp_pkey);
                }
            }

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
            for (int i = 0; i < ecc_pref->count; i++) {
                server_ecc_evp_params = &server_conn->secure.client_ecc_evp_params[i];
                client_ecc_evp_params = &client_conn->secure.client_ecc_evp_params[i];

                EXPECT_NOT_NULL(server_ecc_evp_params->negotiated_curve);
                EXPECT_NOT_NULL(server_ecc_evp_params->evp_pkey);
                EXPECT_TRUE(s2n_public_ecc_keys_are_equal(server_ecc_evp_params, client_ecc_evp_params));
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
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

            /* should not have initialized any other curves */
            for (int i = 1; i < ecc_pref->count; i++) {
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
            conn->actual_protocol_version = S2N_TLS13;
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
            conn->actual_protocol_version = S2N_TLS13;
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
            server_conn->actual_protocol_version = S2N_TLS13;
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
            conn->actual_protocol_version = S2N_TLS13;
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
                conn->actual_protocol_version = S2N_TLS13;
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
