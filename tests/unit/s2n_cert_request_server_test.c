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

#include <s2n.h>

#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"
#include "stuffer/s2n_stuffer.h"
#include "s2n_test.h"

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

static uint8_t s2n_cert_type_preference_list_with_dss[] = {
        S2N_CERT_TYPE_RSA_SIGN,
        S2N_CERT_TYPE_DSS_SIGN,
        S2N_CERT_TYPE_ECDSA_SIGN
};

int main(int argc, char **argv)
{

    BEGIN_TEST();

    {
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        s2n_cert_req_send(server_conn);
        struct s2n_stuffer *in = &server_conn->handshake.io;
        uint8_t cert_types_len;

        s2n_stuffer_read_uint8(in, &cert_types_len);

        uint8_t *their_cert_type_pref_list = s2n_stuffer_raw_read(in, cert_types_len);

        EXPECT_EQUAL(cert_types_len, 2);
        for (int idx = 0; idx < sizeof(s2n_cert_type_preference_list); idx++) {
            EXPECT_EQUAL(their_cert_type_pref_list[idx], s2n_cert_type_preference_list[idx]);
        }
    }

    {
        EXPECT_SUCCESS(setenv("S2N_ENABLE_CERT_REQ_DSS_SIGN", "1", 0));

        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        s2n_cert_req_send(server_conn);
        struct s2n_stuffer *in = &server_conn->handshake.io;
        uint8_t cert_types_len;

        s2n_stuffer_read_uint8(in, &cert_types_len);

        uint8_t *their_cert_type_pref_list = s2n_stuffer_raw_read(in, cert_types_len);

        EXPECT_EQUAL(cert_types_len, 3);
        for (int idx = 0; idx < sizeof(s2n_cert_type_preference_list); idx++) {
            EXPECT_EQUAL(their_cert_type_pref_list[idx], s2n_cert_type_preference_list_with_dss[idx]);
        }
    }

    END_TEST();
    return 0;
}