/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"

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
        EXPECT_SUCCESS(s2n_extensions_client_key_share_send(conn, &key_share_extension));
        EXPECT_EQUAL(key_share_size, s2n_stuffer_data_available(&key_share_extension));

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test s2n_extensions_key_share_send */
    {
        /* Test that s2n_extensions_key_share_send initializes the client key share list */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_send(conn, &key_share_extension));

            for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_EQUAL(ecc_evp_params->negotiated_curve, s2n_ecc_evp_supported_curves_list[i]);
                EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_key_share_send writes a well-formed list of key shares */
        {
            struct s2n_stuffer key_share_extension;
            struct s2n_connection *conn;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_send(conn, &key_share_extension));

            /* should start with correct extension type */
            uint16_t extension_type;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &extension_type));
            EXPECT_EQUAL(extension_type, TLS_EXTENSION_KEY_SHARE);

            /* should start with correct extension size */
            uint16_t extension_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &extension_size));
            uint16_t actual_extension_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_EQUAL(extension_size, actual_extension_size);

            /* should have correct shares size */
            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            uint16_t actual_key_shares_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_EQUAL(key_shares_size, actual_key_shares_size);

            /* should contain every supported curve, in order, with their sizes */
            for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                uint16_t iana_value, share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
                EXPECT_EQUAL(iana_value, s2n_ecc_evp_supported_curves_list[i]->iana_id);
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
                EXPECT_EQUAL(share_size, s2n_ecc_evp_supported_curves_list[i]->share_size);

                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test s2n_extensions_client_key_share_recv */
    {
        /* Test that s2n_extensions_client_key_share_recv can read and parse
         * the result of s2n_extensions_key_share_send */
        {
            struct s2n_connection *client_conn, *server_conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_send(client_conn, &key_share_extension));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, 4));
            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(server_conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should set internal state the same as the client */
            struct s2n_ecc_evp_params *server_ecc_evp_params;
            struct s2n_ecc_evp_params *client_ecc_evp_params;
            for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
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

        /* Test that s2n_extensions_client_key_share_recv errors on client shares size larger
         * than available data */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, s2n_ecc_evp_supported_curves_list[0]->share_size * 10));
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, s2n_ecc_evp_supported_curves_list[0]));

            EXPECT_FAILURE(s2n_extensions_client_key_share_recv(conn, &key_share_extension));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_client_key_share_recv errors on key share size longer than data */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            /* Write curve with huge length */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    s2n_ecc_evp_supported_curves_list[0]->iana_id, s2n_ecc_evp_supported_curves_list[0]->share_size * 10, s2n_ecc_evp_supported_curves_list[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_FAILURE(s2n_extensions_client_key_share_recv(conn, &key_share_extension));

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_client_key_share_recv accepts a subset of supported curves */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            /* Write only first curve */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, s2n_ecc_evp_supported_curves_list[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should have initialized first curve */
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[0];
            EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
            EXPECT_EQUAL(ecc_evp_params->negotiated_curve, s2n_ecc_evp_supported_curves_list[0]);

            /* should not have initialized any other curves */
            for (int i = 1; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_client_key_share_recv handles empty client share list */
        {
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, 0));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(server_conn, &key_share_extension));

            /* should not have initialized any other curves */
            for (int i = 1; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &server_conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test that s2n_extensions_client_key_share_recv ignores unsupported curves */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            S2N_PREPARE_DATA_LENGTH(&key_share_extension);

            /* Write unsupported curves */
            /* 0 -> unallocated_RESERVED */
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    0, s2n_ecc_evp_supported_curves_list[0]->share_size, s2n_ecc_evp_supported_curves_list[0]));
            /* 0xFF01 -> obsolete_RESERVED */
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    65281, s2n_ecc_evp_supported_curves_list[0]->share_size, s2n_ecc_evp_supported_curves_list[0]));

            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_client_key_share_recv ignores curves with incorrect key size */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            /* Write supported curve, but with a different curve's size */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_key_share(&key_share_extension,
                    s2n_ecc_evp_supported_curves_list[0]->iana_id, s2n_ecc_evp_supported_curves_list[1]->share_size, s2n_ecc_evp_supported_curves_list[1]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_client_key_share_recv uses first instance of duplicate curves */
        {
            struct s2n_connection *server_conn;
            struct s2n_stuffer key_share_extension;
            struct s2n_ecc_evp_params first_params, second_params;
            int supported_curve_index = 0;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            S2N_PREPARE_DATA_LENGTH(&key_share_extension);

            /* Write first curve once */
            first_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[supported_curve_index];
            first_params.evp_pkey = NULL;
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&first_params, &key_share_extension));

            /* Write first curve again */
            second_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[supported_curve_index];
            second_params.evp_pkey = NULL;
            EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&second_params, &key_share_extension));

            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(server_conn, &key_share_extension));

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

        /* Test that s2n_extensions_client_key_share_recv ignores points that can't be parsed */
        {
            struct s2n_connection *conn;
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(NULL)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            /* Write first curve */
            S2N_PREPARE_DATA_LENGTH(&key_share_extension);
            EXPECT_SUCCESS(s2n_write_named_curve(&key_share_extension, s2n_ecc_evp_supported_curves_list[0]));
            S2N_WRITE_DATA_LENGTH(&key_share_extension);

            /* Mess up point by erasing most of it */
            int data_size = s2n_stuffer_data_available(&key_share_extension);
            GUARD(s2n_stuffer_wipe_n(&key_share_extension, data_size / 2));
            GUARD(s2n_stuffer_skip_write(&key_share_extension, data_size / 2));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(conn, &key_share_extension));

            /* should read all data */
            EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

            /* should not have initialized any curves */
            for (int i = 1; i < s2n_ecc_evp_supported_curves_list_len; i++) {
                struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
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
