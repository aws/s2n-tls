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

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"

/*
 * Definitions in s2n_server_cert_request.c
 */
typedef enum {
    S2N_CERT_TYPE_RSA_SIGN = 1,
    S2N_CERT_TYPE_DSS_SIGN = 2,
    S2N_CERT_TYPE_RSA_FIXED_DH = 3,
    S2N_CERT_TYPE_DSS_FIXED_DH = 4,
    S2N_CERT_TYPE_RSA_EPHEMERAL_DH_RESERVED = 5,
    S2N_CERT_TYPE_DSS_EPHEMERAL_DH_RESERVED = 6,
    S2N_CERT_TYPE_FORTEZZA_DMS_RESERVED = 20,
    S2N_CERT_TYPE_ECDSA_SIGN = 64,
    S2N_CERT_TYPE_RSA_FIXED_ECDH = 65,
    S2N_CERT_TYPE_ECDSA_FIXED_ECDH = 66,
} s2n_cert_type;

static uint8_t s2n_cert_type_preference_list[] = {
    S2N_CERT_TYPE_RSA_SIGN,
    S2N_CERT_TYPE_ECDSA_SIGN
};

static uint8_t s2n_cert_type_preference_list_legacy_dss[] = {
    S2N_CERT_TYPE_RSA_SIGN,
    S2N_CERT_TYPE_DSS_SIGN,
    S2N_CERT_TYPE_ECDSA_SIGN
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test server cert request default behavior when s2n_config_enable_cert_req_dss_legacy_compat is not called
     * Certificate types enabled should be in s2n_cert_type_preference_list */
    {
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *server_config = NULL;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_cert_req_send(server_conn));
        struct s2n_stuffer *in = &server_conn->handshake.io;
        uint8_t cert_types_len = 0;

        EXPECT_SUCCESS(s2n_stuffer_read_uint8(in, &cert_types_len));

        uint8_t *their_cert_type_pref_list = s2n_stuffer_raw_read(in, cert_types_len);

        EXPECT_EQUAL(cert_types_len, s2n_array_len(s2n_cert_type_preference_list));
        for (size_t idx = 0; idx < s2n_array_len(s2n_cert_type_preference_list); idx++) {
            EXPECT_EQUAL(their_cert_type_pref_list[idx], s2n_cert_type_preference_list[idx]);
        }

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test certificate types in server cert request when s2n_config_enable_cert_req_dss_legacy_compat is called
     * Certificate types enabled should be in s2n_cert_type_preference_list_legacy_dss */
    {
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *server_config = NULL;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_config_enable_cert_req_dss_legacy_compat(server_config));

        EXPECT_SUCCESS(s2n_cert_req_send(server_conn));
        struct s2n_stuffer *in = &server_conn->handshake.io;
        uint8_t cert_types_len = 0;

        EXPECT_SUCCESS(s2n_stuffer_read_uint8(in, &cert_types_len));

        uint8_t *their_cert_type_pref_list = s2n_stuffer_raw_read(in, cert_types_len);

        EXPECT_EQUAL(cert_types_len, s2n_array_len(s2n_cert_type_preference_list_legacy_dss));
        for (size_t idx = 0; idx < s2n_array_len(s2n_cert_type_preference_list_legacy_dss); idx++) {
            EXPECT_EQUAL(their_cert_type_pref_list[idx], s2n_cert_type_preference_list_legacy_dss[idx]);
        }

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test: certificate_authorities supported */
    {
        /* Test: no cert_authorities sent by default */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_cert_req_send(conn));
            struct s2n_stuffer *output = &conn->handshake.io;

            uint8_t cert_types_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(output, &cert_types_len));
            EXPECT_TRUE(cert_types_len > 0);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(output, cert_types_len));

            uint16_t sig_algs_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(output, &sig_algs_len));
            EXPECT_TRUE(sig_algs_len > 0);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(output, sig_algs_len));

            uint16_t cert_authorities_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(output, &cert_authorities_len));
            EXPECT_EQUAL(cert_authorities_len, 0);

            EXPECT_EQUAL(s2n_stuffer_data_available(output), 0);
        };

        /* Test: cert_authorities sent if configured */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* If we use TLS1.1 instead of TLS1.2, we don't need to worry about
             * skipping the signature algorithms.
             */
            conn->actual_protocol_version = S2N_TLS11;

            const uint8_t ca_data[] = "these are my CAs";
            EXPECT_SUCCESS(s2n_alloc(&config->cert_authorities, sizeof(ca_data)));
            EXPECT_MEMCPY_SUCCESS(config->cert_authorities.data, ca_data, sizeof(ca_data));

            EXPECT_SUCCESS(s2n_cert_req_send(conn));
            struct s2n_stuffer *output = &conn->handshake.io;

            uint8_t cert_types_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(output, &cert_types_len));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(output, cert_types_len));

            uint16_t cert_authorities_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(output, &cert_authorities_len));
            EXPECT_EQUAL(cert_authorities_len, sizeof(ca_data));

            uint8_t *cert_authorities_data = s2n_stuffer_raw_read(output, cert_authorities_len);
            EXPECT_NOT_NULL(cert_authorities_data);
            EXPECT_BYTEARRAY_EQUAL(cert_authorities_data, ca_data, sizeof(ca_data));

            EXPECT_EQUAL(s2n_stuffer_data_available(output), 0);
        };
    };

    END_TEST();
}
