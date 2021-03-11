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

#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_resume.h"
/* To test static function */
#include "tls/s2n_resume.c"

#define S2N_TLS13_STATE_SIZE_WITHOUT_SECRET S2N_MAX_STATE_SIZE_IN_BYTES - S2N_TLS_SECRET_LEN

static int s2n_test_session_ticket_callback(struct s2n_connection *conn, struct s2n_session_ticket *ticket)
{
    return S2N_SUCCESS;
}

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

    /* s2n_tls12_serialize_resumption_state */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_blob blob = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&blob, conn->secure.master_secret, S2N_TLS_SECRET_LEN));
        EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &blob));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, test_master_secret.data, S2N_TLS_SECRET_LEN));
        conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

        uint8_t s_data[S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = { 0 };
        struct s2n_blob state_blob = { 0 };
        POSIX_GUARD(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
        struct s2n_stuffer output = { 0 };

        POSIX_GUARD(s2n_stuffer_init(&output, &state_blob));
        EXPECT_SUCCESS(s2n_tls12_serialize_resumption_state(conn, &output));

        uint8_t serial_id = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &serial_id));
        EXPECT_EQUAL(serial_id, S2N_TLS12_SERIALIZED_FORMAT_VERSION);

        uint8_t version = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &version));
        EXPECT_EQUAL(version, S2N_TLS12);

        uint8_t iana_value[2] = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, iana_value, S2N_TLS_CIPHER_SUITE_LEN));
        EXPECT_BYTEARRAY_EQUAL(conn->secure.cipher_suite->iana_value, &iana_value, S2N_TLS_CIPHER_SUITE_LEN);

        /* Current time */
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, sizeof(uint64_t)));

        uint8_t master_secret[S2N_TLS_SECRET_LEN] = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, master_secret, S2N_TLS_SECRET_LEN));
        EXPECT_BYTEARRAY_EQUAL(test_master_secret.data, master_secret, S2N_TLS_SECRET_LEN);
        
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    
    /* s2n_tls13_serialize_resumption_state */
    {
        /* Safety checks */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            struct s2n_stuffer output = { 0 };
            struct s2n_ticket_fields ticket_fields = { 0 };

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(NULL, &ticket_fields, &output), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(conn, NULL, &output), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(conn, &ticket_fields, NULL), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS1.3 serialization */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;

            conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_session_secret };

            EXPECT_OK(s2n_tls13_serialize_resumption_state(conn, &ticket_fields, &output));

            uint8_t serial_id = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &serial_id));
            EXPECT_EQUAL(serial_id, S2N_TLS13_SERIALIZED_FORMAT_VERSION);

            uint8_t version = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &version));
            EXPECT_EQUAL(version, S2N_TLS13);

            uint8_t iana_value[2] = { 0 };
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

            uint8_t session_secret[S2N_TLS_SECRET_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, session_secret, secret_len));
            EXPECT_BYTEARRAY_EQUAL(test_session_secret.data, session_secret, secret_len);
            
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Erroneous secret size */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_session_secret };

            ticket_fields.session_secret.size = UINT8_MAX + 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_serialize_resumption_state(conn, &ticket_fields, &output), S2N_ERR_SAFETY);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* s2n_encrypt_session_ticket */
    {
        /* Session ticket keys. Taken from test vectors in https://tools.ietf.org/html/rfc5869 */
        uint8_t ticket_key_name[16] = "2016.07.26.15\0";
        S2N_BLOB_FROM_HEX(ticket_key, 
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

        /* Check encrypted data can be decrypted correctly for TLS12 */
        {
            struct s2n_connection *conn;
            struct s2n_config *config;
            uint64_t current_time;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                         ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_blob secret = { 0 };
            struct s2n_stuffer secret_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&secret, conn->secure.master_secret, S2N_TLS_SECRET_LEN));
            EXPECT_SUCCESS(s2n_stuffer_init(&secret_stuffer, &secret));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&secret_stuffer, test_master_secret.data, S2N_TLS_SECRET_LEN));
            conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

            uint8_t data[S2N_TLS12_TICKET_SIZE_IN_BYTES] = { 0 };
            struct s2n_blob blob = { 0 };
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_SUCCESS(s2n_stuffer_init(&output, &blob));

            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, NULL, &output));

            /* Wiping the master secret to prove that the decryption function actually writes the master secret */
            memset(conn->secure.master_secret, 0, test_master_secret.size);

            conn->client_ticket_to_decrypt = output;
            EXPECT_SUCCESS(s2n_decrypt_session_ticket(conn));

            /* Check decryption was successful by comparing master key */
            EXPECT_BYTEARRAY_EQUAL(conn->secure.master_secret, test_master_secret.data, test_master_secret.size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Check session ticket size is correct for a small secret in TLS13 session resumption. The 
         * contents of the encrypted output will be tested once the TLS1.3 deserialization function
         * is written. */
        {
            struct s2n_connection *conn;
            struct s2n_config *config;
            uint64_t current_time;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            /* Setting up session resumption encryption key */
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                         ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;

            uint8_t data[S2N_TICKET_KEY_NAME_LEN + S2N_TLS_GCM_IV_LEN + S2N_MAX_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = { 0 };
            struct s2n_blob blob = { 0 };
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_SUCCESS(s2n_stuffer_init(&output, &blob));
            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_session_secret };

            /* This secret is smaller than the maximum secret length */
            EXPECT_TRUE(ticket_fields.session_secret.size < S2N_TLS_SECRET_LEN);

            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket_fields, &output));

            uint32_t expected_size = S2N_TICKET_KEY_NAME_LEN + S2N_TLS_GCM_IV_LEN + 
                        S2N_TLS13_STATE_SIZE_WITHOUT_SECRET + test_session_secret.size + S2N_TLS_GCM_TAG_LEN;
            EXPECT_EQUAL(expected_size, s2n_stuffer_data_available(&output));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Check session ticket size is correct for the maximum size secret in TLS13 session resumption. The 
         * contents of the encrypted output will be tested once the TLS1.3 deserialization function
         * is written. */
        {
            struct s2n_connection *conn;
            struct s2n_config *config;
            uint64_t current_time;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            /* Setting up session resumption encryption key */
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                         ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;

            uint8_t data[S2N_TICKET_KEY_NAME_LEN + S2N_TLS_GCM_IV_LEN + S2N_MAX_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = { 0 };
            struct s2n_blob blob = { 0 };
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_SUCCESS(s2n_stuffer_init(&output, &blob));
            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_master_secret };

            /* This secret is equal to the maximum secret length */
            EXPECT_EQUAL(ticket_fields.session_secret.size, S2N_TLS_SECRET_LEN);

            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket_fields, &output));

            uint32_t expected_size = S2N_TICKET_KEY_NAME_LEN + S2N_TLS_GCM_IV_LEN + 
                        S2N_TLS13_STATE_SIZE_WITHOUT_SECRET + S2N_TLS_SECRET_LEN + S2N_TLS_GCM_TAG_LEN;
            EXPECT_EQUAL(expected_size, s2n_stuffer_data_available(&output));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* s2n_config_set_initial_ticket_count */
    {
        struct s2n_connection *conn;
        struct s2n_config *config;
        uint8_t num_tickets = 1;

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_EQUAL(conn->tickets_to_send, 0);

        EXPECT_SUCCESS(s2n_config_set_initial_ticket_count(config, num_tickets));

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_EQUAL(conn->tickets_to_send, num_tickets);

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* s2n_connection_add_new_tickets_to_send */
    {
        /* New number of session tickets can be set */
        {
            struct s2n_connection *conn;
            uint8_t original_num_tickets = 1;
            uint8_t new_num_tickets = 10;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->tickets_to_send = original_num_tickets;

            EXPECT_SUCCESS(s2n_connection_add_new_tickets_to_send(conn, new_num_tickets));

            EXPECT_EQUAL(conn->tickets_to_send, original_num_tickets + new_num_tickets);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Overflow error is caught */
        {
            struct s2n_connection *conn;
            uint8_t new_num_tickets = 1;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->tickets_to_send = UINT16_MAX;

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_add_new_tickets_to_send(conn, new_num_tickets), S2N_ERR_INTEGER_OVERFLOW);
            
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* s2n_config_set_session_ticket_cb */
    {
        struct s2n_config *config = NULL;
        EXPECT_NOT_NULL(config = s2n_config_new());
        void *ctx = NULL;

        /* Safety check */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_session_ticket_cb(NULL, s2n_test_session_ticket_callback, ctx), S2N_ERR_NULL);
        }

        EXPECT_NULL(config->session_ticket_cb);
        EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_callback, ctx));
        EXPECT_EQUAL(config->session_ticket_cb, s2n_test_session_ticket_callback);
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* s2n_session_ticket_get_data_len */
    {
        /* Safety checks */
        {
            struct s2n_session_ticket session_ticket = { 0 };
            size_t data_len = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_data_len(NULL, &data_len), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_data_len(&session_ticket, NULL), S2N_ERR_NULL);
        }

        /* Empty ticket */
        {
            struct s2n_session_ticket session_ticket = { 0 };
            size_t data_len = 0;
            EXPECT_SUCCESS(s2n_session_ticket_get_data_len(&session_ticket, &data_len));
            EXPECT_EQUAL(data_len, 0);
        }

        /* Valid ticket */
        {
            uint8_t ticket_data[] = "session ticket data";
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, ticket_data, sizeof(ticket_data)));
            struct s2n_session_ticket session_ticket = { .ticket_data = ticket_blob };

            size_t data_len = 0;
            EXPECT_SUCCESS(s2n_session_ticket_get_data_len(&session_ticket, &data_len));
            EXPECT_EQUAL(data_len, sizeof(ticket_data));
        }
    }

    /* s2n_session_ticket_get_data */
    {
        /* Safety checks */
        {
            struct s2n_session_ticket session_ticket = { 0 };
            size_t max_data_len = 0;
            uint8_t *data = NULL;
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_data(NULL, max_data_len, data), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_data(&session_ticket, max_data_len, NULL), S2N_ERR_NULL);
        }

        /* Valid ticket */
        {
            uint8_t ticket_data[] = "session ticket data";
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, ticket_data, sizeof(ticket_data)));
            struct s2n_session_ticket session_ticket = { .ticket_data = ticket_blob };

            uint8_t data[sizeof(ticket_data)];
            size_t max_data_len = sizeof(data);
            EXPECT_SUCCESS(s2n_session_ticket_get_data(&session_ticket, max_data_len, data));
            EXPECT_BYTEARRAY_EQUAL(data, ticket_data, sizeof(ticket_data));
        }

        /* Ticket data is larger than customer buffer */
        {
            uint8_t ticket_data[] = "session ticket data";
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, ticket_data, sizeof(ticket_data)));
            struct s2n_session_ticket session_ticket = { .ticket_data = ticket_blob };

            uint8_t data[sizeof(ticket_data) - 1];
            size_t max_data_len = sizeof(data);
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_data(&session_ticket, max_data_len, data),
                    S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG);
        }
    }

    /* s2n_session_ticket_get_lifetime */
    {
        /* Safety checks */
        {
            struct s2n_session_ticket session_ticket = { 0 };
            uint32_t lifetime = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_lifetime(NULL, &lifetime), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_session_ticket_get_lifetime(&session_ticket, NULL), S2N_ERR_NULL);
        }

        /* Valid lifetime */
        {
            uint32_t lifetime = 100;
            struct s2n_session_ticket session_ticket = { .session_lifetime = lifetime };

            uint32_t ticket_lifetime = 0;
            EXPECT_SUCCESS(s2n_session_ticket_get_lifetime(&session_ticket, &ticket_lifetime));
            EXPECT_EQUAL(lifetime, ticket_lifetime);
        }
    }

    END_TEST();
}
