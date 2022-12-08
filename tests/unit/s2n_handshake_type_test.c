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

#include <sys/param.h>

#include "s2n_test.h"
#include "tls/s2n_connection.h"

#define S2N_FIRST_COMMON_HANDSHAKE_FLAG NEGOTIATED
#define S2N_LAST_COMMON_HANDSHAKE_FLAG  NO_CLIENT_CERT
#define S2N_FIRST_TLS12_HANDSHAKE_FLAG  TLS12_PERFECT_FORWARD_SECRECY
#define S2N_LAST_TLS12_HANDSHAKE_FLAG   WITH_SESSION_TICKET
#define S2N_FIRST_TLS13_HANDSHAKE_FLAG  HELLO_RETRY_REQUEST
#define S2N_LAST_TLS13_HANDSHAKE_FLAG   EARLY_CLIENT_CCS

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Sanity check test setup */
    EXPECT_EQUAL(S2N_FIRST_COMMON_HANDSHAKE_FLAG, 1);
    EXPECT_TRUE(S2N_FIRST_COMMON_HANDSHAKE_FLAG < S2N_LAST_COMMON_HANDSHAKE_FLAG);
    EXPECT_EQUAL(S2N_FIRST_TLS12_HANDSHAKE_FLAG, S2N_LAST_COMMON_HANDSHAKE_FLAG * 2);
    EXPECT_TRUE(S2N_FIRST_TLS12_HANDSHAKE_FLAG < S2N_LAST_TLS12_HANDSHAKE_FLAG);
    EXPECT_EQUAL(S2N_FIRST_TLS13_HANDSHAKE_FLAG, S2N_LAST_COMMON_HANDSHAKE_FLAG * 2);
    EXPECT_TRUE(S2N_FIRST_TLS13_HANDSHAKE_FLAG < S2N_LAST_TLS13_HANDSHAKE_FLAG);
    EXPECT_EQUAL(MAX(S2N_LAST_TLS12_HANDSHAKE_FLAG, S2N_LAST_TLS13_HANDSHAKE_FLAG), S2N_HANDSHAKES_COUNT / 2);

    /* Test s2n_handshake_type_reset */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        conn->handshake.handshake_type = 0x12AB;
        EXPECT_OK(s2n_handshake_type_reset(conn));
        EXPECT_EQUAL(conn->handshake.handshake_type, 0);

        EXPECT_OK(s2n_handshake_type_set_flag(conn, FULL_HANDSHAKE));
        EXPECT_OK(s2n_handshake_type_reset(conn));
        EXPECT_EQUAL(conn->handshake.handshake_type, 0);

        EXPECT_OK(s2n_handshake_type_set_flag(conn, 0xFFFF));
        EXPECT_OK(s2n_handshake_type_reset(conn));
        EXPECT_EQUAL(conn->handshake.handshake_type, 0);

        EXPECT_OK(s2n_handshake_type_set_flag(conn, 0));
        EXPECT_OK(s2n_handshake_type_reset(conn));
        EXPECT_EQUAL(conn->handshake.handshake_type, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_handshake_type_set_flag */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_flag(NULL, 0), S2N_ERR_NULL);

        /* Sets all common flags */
        for (s2n_handshake_type_flag flag = S2N_FIRST_COMMON_HANDSHAKE_FLAG; flag <= S2N_LAST_COMMON_HANDSHAKE_FLAG; flag++) {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_OK(s2n_handshake_type_set_flag(conn, flag));
            EXPECT_EQUAL(conn->handshake.handshake_type, flag);

            EXPECT_OK(s2n_handshake_type_reset(conn));

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_handshake_type_set_flag(conn, flag));
            EXPECT_EQUAL(conn->handshake.handshake_type, flag);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    /* Test s2n_handshake_type_check_flag */
    {
        /* Safety */
        EXPECT_FALSE(s2n_handshake_type_check_flag(NULL, 0));

        /* Check when common flags set */
        for (s2n_handshake_type_flag flag = S2N_FIRST_COMMON_HANDSHAKE_FLAG; flag <= S2N_LAST_COMMON_HANDSHAKE_FLAG; flag++) {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            /* All flags set */
            {
                conn->handshake.handshake_type = 0xFFFF;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_TRUE(s2n_handshake_type_check_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_TRUE(s2n_handshake_type_check_flag(conn, flag));
            };

            /* No flags set */
            {
                conn->handshake.handshake_type = 0;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_FALSE(s2n_handshake_type_check_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_FALSE(s2n_handshake_type_check_flag(conn, flag));
            };

            /* One flag set */
            {
                conn->handshake.handshake_type = flag;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_TRUE(s2n_handshake_type_check_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_TRUE(s2n_handshake_type_check_flag(conn, flag));
            };

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    /* Test s2n_handshake_type_set_tls12_flag */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_tls12_flag(NULL, 0), S2N_ERR_NULL);

        /* Sets all TLS1.2 flags */
        for (s2n_tls12_handshake_type_flag flag = S2N_FIRST_TLS12_HANDSHAKE_FLAG; flag <= S2N_LAST_TLS12_HANDSHAKE_FLAG; flag++) {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_OK(s2n_handshake_type_set_tls12_flag(conn, flag));
            EXPECT_EQUAL(conn->handshake.handshake_type, flag);

            EXPECT_OK(s2n_handshake_type_reset(conn));

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_tls12_flag(conn, flag), S2N_ERR_HANDSHAKE_STATE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    /* Test s2n_handshake_type_check_tls12_flag */
    {
        /* Safety */
        EXPECT_FALSE(s2n_handshake_type_check_tls12_flag(NULL, 0));

        /* Check when common flags set */
        for (s2n_tls12_handshake_type_flag flag = S2N_FIRST_TLS12_HANDSHAKE_FLAG; flag <= S2N_LAST_TLS12_HANDSHAKE_FLAG; flag++) {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            /* All flags set */
            {
                conn->handshake.handshake_type = 0xFFFF;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_TRUE(s2n_handshake_type_check_tls12_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_FALSE(s2n_handshake_type_check_tls12_flag(conn, flag));
            };

            /* No flags set */
            {
                conn->handshake.handshake_type = 0;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_FALSE(s2n_handshake_type_check_tls12_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_FALSE(s2n_handshake_type_check_tls12_flag(conn, flag));
            };

            /* One flag set */
            {
                conn->handshake.handshake_type = flag;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_TRUE(s2n_handshake_type_check_tls12_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_FALSE(s2n_handshake_type_check_tls12_flag(conn, flag));
            };

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    /* Test s2n_handshake_type_set_tls13_flag */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_tls13_flag(NULL, 0), S2N_ERR_NULL);

        /* Sets all TLS1.3 flags */
        for (s2n_tls13_handshake_type_flag flag = S2N_FIRST_TLS13_HANDSHAKE_FLAG; flag <= S2N_LAST_TLS13_HANDSHAKE_FLAG; flag++) {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_handshake_type_set_tls13_flag(conn, flag));
            EXPECT_EQUAL(conn->handshake.handshake_type, flag);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_tls13_flag(conn, flag), S2N_ERR_HANDSHAKE_STATE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    /* Test s2n_handshake_type_check_tls13_flag */
    {
        /* Safety */
        EXPECT_FALSE(s2n_handshake_type_check_tls13_flag(NULL, 0));

        /* Check when common flags set */
        for (s2n_tls13_handshake_type_flag flag = S2N_FIRST_TLS13_HANDSHAKE_FLAG; flag <= S2N_LAST_TLS13_HANDSHAKE_FLAG; flag++) {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            /* All flags set */
            {
                conn->handshake.handshake_type = 0xFFFF;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_FALSE(s2n_handshake_type_check_tls13_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_TRUE(s2n_handshake_type_check_tls13_flag(conn, flag));
            };

            /* No flags set */
            {
                conn->handshake.handshake_type = 0;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_FALSE(s2n_handshake_type_check_tls13_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_FALSE(s2n_handshake_type_check_tls13_flag(conn, flag));
            };

            /* One flag set */
            {
                conn->handshake.handshake_type = flag;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_FALSE(s2n_handshake_type_check_tls13_flag(conn, flag));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_TRUE(s2n_handshake_type_check_tls13_flag(conn, flag));
            };

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    END_TEST();
}
