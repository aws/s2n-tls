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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

/* To test static function */
#include "tls/s2n_resume.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Two random secrets of different sizes */
    S2N_BLOB_FROM_HEX(test_master_secret,
    "ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd"
    "531be2441d7c63e2b9729d145c11d84af35957727565a4");

    S2N_BLOB_FROM_HEX(test_session_secret,
    "18df06843d13a08bf2a449844c5f8a"
    "478001bc4d4c627984d5a41da8d0402919");

    /* s2n_serialize_resumption_state */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_blob blob = {0};
        struct s2n_stuffer stuffer = {0};
        EXPECT_SUCCESS(s2n_blob_init(&blob, conn->secure.master_secret, S2N_TLS_SECRET_LEN));
        EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &blob));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, test_master_secret.data, S2N_TLS_SECRET_LEN));
        conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

        uint8_t s_data[S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = { 0 };
        struct s2n_blob state_blob = {0};
        GUARD(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
        struct s2n_stuffer output = {0};

        GUARD(s2n_stuffer_init(&output, &state_blob));
        EXPECT_SUCCESS(s2n_serialize_resumption_state(conn, &output));

        uint8_t serial_id = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &serial_id));
        EXPECT_EQUAL(serial_id, S2N_TLS12_SERIALIZED_FORMAT_VERSION);

        uint8_t version = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &version));
        EXPECT_EQUAL(version, S2N_TLS12);

        uint8_t iana_value[2] = {0};
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, iana_value, S2N_TLS_CIPHER_SUITE_LEN));
        EXPECT_BYTEARRAY_EQUAL(conn->secure.cipher_suite->iana_value, &iana_value, S2N_TLS_CIPHER_SUITE_LEN);

        /* Current time */
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, sizeof(uint64_t)));

        uint8_t master_secret[S2N_TLS_SECRET_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, master_secret, S2N_TLS_SECRET_LEN));
        EXPECT_BYTEARRAY_EQUAL(test_master_secret.data, master_secret, S2N_TLS_SECRET_LEN);
        
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    
    /* s2n_tls13_serialize_resumption_state */
    {
        /* Safety checks */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            struct s2n_stuffer output = {0};
            struct s2n_ticket_fields ticket_fields = {0};

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(NULL, &ticket_fields, &output), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(conn, NULL, &output), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(conn, &ticket_fields, NULL), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS1.3 serialization */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->actual_protocol_version = S2N_TLS13;

            conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer output = {0}, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_session_secret };

            EXPECT_OK(s2n_tls13_serialize_resumption_state(conn, &ticket_fields, &output));

            uint8_t serial_id = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &serial_id));
            EXPECT_EQUAL(serial_id, S2N_TLS13_SERIALIZED_FORMAT_VERSION);

            uint8_t version = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &version));
            EXPECT_EQUAL(version, S2N_TLS13);

            uint8_t iana_value[2] = {0};
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, iana_value, S2N_TLS_CIPHER_SUITE_LEN));
            EXPECT_BYTEARRAY_EQUAL(conn->secure.cipher_suite->iana_value, &iana_value, S2N_TLS_CIPHER_SUITE_LEN);

            /* Current time */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, sizeof(uint64_t)));

            uint32_t ticket_age_add = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &ticket_age_add));
            EXPECT_EQUAL(ticket_age_add, ticket_fields.ticket_age_add);

            uint8_t secret_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &secret_len));
            EXPECT_EQUAL(secret_len, ticket_fields.session_secret.size);

            uint8_t session_secret[S2N_TLS_SECRET_LEN] = {0};
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, session_secret, secret_len));
            EXPECT_BYTEARRAY_EQUAL(test_session_secret.data, session_secret, secret_len);
            
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }
    END_TEST();
}
