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
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_resume.h"
/* To test static function */
#include "tls/s2n_resume.c"
#include "utils/s2n_safety.h"

#define TICKET_ISSUE_TIME_BYTES 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
#define TICKET_AGE_ADD_BYTES 0x01, 0x01, 0x01, 0x01
#define TICKET_AGE_ADD 16843009
#define SECRET_LEN 0x02
#define SECRET 0x03, 0x04
#define EMPTY_EARLY_DATA_SIZE 0x00, 0x00, 0x00, 0x00
#define CLIENT_TICKET 0x10, 0x10

#define NONEMPTY_EARLY_DATA_SIZE 0x12
#define APP_PROTOCOL_LEN 0x02
#define APP_PROTOCOL 0x05, 0x06
#define EARLY_DATA_CONTEXT_LEN 0x03
#define EARLY_DATA_CONTEXT 0x07, 0x08, 0x09

#define SECONDS_TO_NANOS(seconds) ((seconds) * (uint64_t)ONE_SEC_IN_NANOS)

const uint64_t ticket_issue_time = 283686952306183;
static int s2n_test_session_ticket_callback(struct s2n_connection *conn, struct s2n_session_ticket *ticket)
{
    return S2N_SUCCESS;
}

static int mock_time(void *data, uint64_t *nanoseconds)
{
    *nanoseconds = ticket_issue_time;
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

        uint8_t s_data[S2N_TLS12_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = { 0 };
        struct s2n_blob state_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
        struct s2n_stuffer output = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &state_blob));
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

        uint32_t tls13_state_size_without_early_data = 0;

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
            tls13_state_size_without_early_data = s2n_stuffer_data_available(&output);

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
            
            uint32_t max_early_data_size = 1;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &max_early_data_size));
            EXPECT_EQUAL(max_early_data_size, 0);

            EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS1.3 serialization with early data */
        {
            const uint32_t test_max_early_data_size = UINT8_MAX;
            const uint8_t test_early_data_context[] = "context";
            const uint8_t test_app_protocol[] = "protocol";

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, test_max_early_data_size));
            EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn, test_early_data_context, sizeof(test_early_data_context)));
            EXPECT_MEMCPY_SUCCESS(conn->application_protocol, test_app_protocol, sizeof(test_app_protocol));
            conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_session_secret };

            EXPECT_OK(s2n_tls13_serialize_resumption_state(conn, &ticket_fields, &output));

            uint32_t max_early_data_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, tls13_state_size_without_early_data - sizeof(max_early_data_size)));
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &max_early_data_size));
            EXPECT_EQUAL(max_early_data_size, test_max_early_data_size);

            uint8_t app_protocol_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &app_protocol_size));
            EXPECT_NOT_EQUAL(app_protocol_size, 0);
            EXPECT_EQUAL(app_protocol_size, strlen((const char*) test_app_protocol));

            uint8_t app_protocol[sizeof(test_app_protocol)] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, app_protocol, app_protocol_size));
            EXPECT_BYTEARRAY_EQUAL(app_protocol, test_app_protocol, sizeof(test_app_protocol));

            uint16_t early_data_context_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &early_data_context_size));
            EXPECT_NOT_EQUAL(early_data_context_size, 0);
            EXPECT_EQUAL(early_data_context_size, sizeof(test_early_data_context));

            uint8_t early_data_context[sizeof(test_early_data_context)] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, early_data_context, early_data_context_size));
            EXPECT_BYTEARRAY_EQUAL(early_data_context, test_early_data_context, sizeof(test_early_data_context));

            EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);
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

    /* s2n_deserialize_resumption_state */
    {
        uint8_t tls12_ticket[S2N_TLS12_STATE_SIZE_IN_BYTES] = {
            S2N_TLS12_SERIALIZED_FORMAT_VERSION,
            S2N_TLS12,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TICKET_ISSUE_TIME_BYTES,
        };

        uint8_t tls13_ticket[] = {
            S2N_TLS13_SERIALIZED_FORMAT_VERSION,
            S2N_TLS13,
            TLS_AES_128_GCM_SHA256,
            TICKET_ISSUE_TIME_BYTES,
            TICKET_AGE_ADD_BYTES,
            SECRET_LEN,
            SECRET,
            EMPTY_EARLY_DATA_SIZE,
        };

        uint8_t tls13_ticket_with_early_data[] = {
            S2N_TLS13_SERIALIZED_FORMAT_VERSION,
            S2N_TLS13,
            TLS_AES_128_GCM_SHA256,
            TICKET_ISSUE_TIME_BYTES,
            TICKET_AGE_ADD_BYTES,
            SECRET_LEN,
            SECRET,
            0x00, 0x00, 0x00, NONEMPTY_EARLY_DATA_SIZE,
            APP_PROTOCOL_LEN,
            APP_PROTOCOL,
            0x00, EARLY_DATA_CONTEXT_LEN,
            EARLY_DATA_CONTEXT,
        };

        uint8_t faulty_format_ticket[] = {
            0xFF,
        };

        /* Serialized ticket with incorrect format errors */
        {
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, faulty_format_ticket, sizeof(faulty_format_ticket)));
            struct s2n_stuffer ticket_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket_stuffer, &ticket_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&ticket_stuffer, sizeof(faulty_format_ticket)));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            EXPECT_ERROR_WITH_ERRNO(s2n_deserialize_resumption_state(conn, NULL, &ticket_stuffer),
                     S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Deserialized ticket sets correct connection values for session resumption in TLS1.2 */
        {
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, tls12_ticket, sizeof(tls12_ticket)));
            struct s2n_stuffer ticket_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket_stuffer, &ticket_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&ticket_stuffer, sizeof(tls12_ticket) - S2N_TLS_SECRET_LEN));
            /* The secret needs to be written to the ticket separately as it has a fixed length */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&ticket_stuffer, test_master_secret.data, S2N_TLS_SECRET_LEN));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            EXPECT_OK(s2n_deserialize_resumption_state(conn, NULL, &ticket_stuffer));

            EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_rsa_with_aes_128_gcm_sha256);

            EXPECT_BYTEARRAY_EQUAL(test_master_secret.data, conn->secure.master_secret, S2N_TLS_SECRET_LEN);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Deserialized ticket sets correct PSK values for session resumption in TLS1.3 */
        {
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, tls13_ticket, sizeof(tls13_ticket)));
            struct s2n_stuffer ticket_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket_stuffer, &ticket_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&ticket_stuffer, sizeof(tls13_ticket)));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Initialize client ticket */
            const uint8_t client_ticket[] = { CLIENT_TICKET };
            EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, sizeof(client_ticket)));
            EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, client_ticket, sizeof(client_ticket));

            EXPECT_OK(s2n_deserialize_resumption_state(conn, &conn->client_ticket, &ticket_stuffer));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);

            EXPECT_EQUAL(psk->type, S2N_PSK_TYPE_RESUMPTION);
            S2N_BLOB_EXPECT_EQUAL(psk->identity, conn->client_ticket);

            EXPECT_EQUAL(psk->secret.size, SECRET_LEN);
            uint8_t secret[] = { SECRET };
            EXPECT_BYTEARRAY_EQUAL(psk->secret.data, secret, sizeof(secret));

            EXPECT_EQUAL(psk->hmac_alg, S2N_HMAC_SHA256);

            EXPECT_EQUAL(psk->ticket_age_add, TICKET_AGE_ADD);
            EXPECT_EQUAL(psk->ticket_issue_time, ticket_issue_time);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Deserialized ticket sets correct PSK values for early data */
        {
            const uint8_t expected_app_protocol[] = { APP_PROTOCOL };
            const uint8_t expected_context[] = { EARLY_DATA_CONTEXT };

            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, tls13_ticket_with_early_data, sizeof(tls13_ticket_with_early_data)));
            struct s2n_stuffer ticket_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket_stuffer, &ticket_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&ticket_stuffer, ticket_blob.size));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Initialize client ticket */
            const uint8_t client_ticket[] = { CLIENT_TICKET };
            EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, sizeof(client_ticket)));
            EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, client_ticket, sizeof(client_ticket));

            EXPECT_OK(s2n_deserialize_resumption_state(conn, &conn->client_ticket, &ticket_stuffer));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);

            EXPECT_EQUAL(psk->early_data_config.protocol_version, S2N_TLS13);
            EXPECT_EQUAL(psk->early_data_config.max_early_data_size, NONEMPTY_EARLY_DATA_SIZE);
            EXPECT_EQUAL(psk->early_data_config.application_protocol.size, APP_PROTOCOL_LEN);
            EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.application_protocol.data, expected_app_protocol, APP_PROTOCOL_LEN);
            EXPECT_EQUAL(psk->early_data_config.context.size, EARLY_DATA_CONTEXT_LEN);
            EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.context.data, expected_context, EARLY_DATA_CONTEXT_LEN);
            EXPECT_EQUAL(psk->early_data_config.cipher_suite, &s2n_tls13_aes_128_gcm_sha256);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Any existing psks are removed when creating a new resumption psk */
        {
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, tls13_ticket, sizeof(tls13_ticket)));
            struct s2n_stuffer ticket_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket_stuffer, &ticket_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&ticket_stuffer, sizeof(tls13_ticket)));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Initialize client ticket */
            uint8_t client_ticket[] = { CLIENT_TICKET };
            EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, sizeof(client_ticket)));
            EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, client_ticket, sizeof(client_ticket));

            /* Add existing resumption psk */
            const uint8_t resumption_data[] = "resumption data";
            DEFER_CLEANUP(struct s2n_psk resumption_psk = { 0 }, s2n_psk_wipe);
            EXPECT_OK(s2n_psk_init(&resumption_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_identity(&resumption_psk, resumption_data, sizeof(resumption_data)));
            EXPECT_SUCCESS(s2n_psk_set_secret(&resumption_psk, resumption_data, sizeof(resumption_data)));
            EXPECT_SUCCESS(s2n_connection_append_psk(conn, &resumption_psk));

            EXPECT_OK(s2n_deserialize_resumption_state(conn, &conn->client_ticket, &ticket_stuffer));

            EXPECT_EQUAL(conn->psk_params.psk_list.len, 1);
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);

            EXPECT_EQUAL(psk->type, S2N_PSK_TYPE_RESUMPTION);
            S2N_BLOB_EXPECT_EQUAL(psk->identity, conn->client_ticket);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Fails if external PSKs already set */
        {
            struct s2n_blob ticket_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, tls13_ticket, sizeof(tls13_ticket)));
            struct s2n_stuffer ticket_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket_stuffer, &ticket_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&ticket_stuffer, sizeof(tls13_ticket)));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Initialize client ticket */
            uint8_t client_ticket[] = { CLIENT_TICKET };
            EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, sizeof(client_ticket)));
            EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, client_ticket, sizeof(client_ticket));

            /* Add existing external psk */
            const uint8_t external_data[] = "external data";
            DEFER_CLEANUP(struct s2n_psk *external_psk = s2n_external_psk_new(), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_set_identity(external_psk, external_data, sizeof(external_data)));
            EXPECT_SUCCESS(s2n_psk_set_secret(external_psk, external_data, sizeof(external_data)));
            EXPECT_SUCCESS(s2n_connection_append_psk(conn, external_psk));

            EXPECT_ERROR_WITH_ERRNO(s2n_deserialize_resumption_state(conn, &conn->client_ticket, &ticket_stuffer), S2N_ERR_PSK_MODE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Functional test: Both TLS1.3 client and server can deserialize what they serialize */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));

            for (s2n_mode mode = S2N_SERVER; mode <= S2N_CLIENT; mode++) {
                struct s2n_connection *conn = s2n_connection_new(mode);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

                conn->actual_protocol_version = S2N_TLS13;
                conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
                DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                struct s2n_ticket_fields ticket_fields = { .ticket_age_add = TICKET_AGE_ADD, .session_secret = test_session_secret };

                /* Initialize client ticket */
                uint8_t client_ticket[] = { CLIENT_TICKET };
                EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, sizeof(client_ticket)));
                EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, client_ticket, sizeof(client_ticket));

                EXPECT_OK(s2n_serialize_resumption_state(conn, &ticket_fields, &stuffer));
                EXPECT_OK(s2n_deserialize_resumption_state(conn, &conn->client_ticket, &stuffer));

                /* Check PSK values are correct */
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
                EXPECT_NOT_NULL(psk);

                EXPECT_EQUAL(psk->type, S2N_PSK_TYPE_RESUMPTION);
                S2N_BLOB_EXPECT_EQUAL(psk->identity, conn->client_ticket);

                EXPECT_EQUAL(psk->secret.size, test_session_secret.size);
                EXPECT_BYTEARRAY_EQUAL(psk->secret.data, test_session_secret.data, test_session_secret.size);

                EXPECT_EQUAL(psk->hmac_alg, conn->secure.cipher_suite->prf_alg);

                EXPECT_EQUAL(psk->ticket_age_add, TICKET_AGE_ADD);
                EXPECT_EQUAL(psk->ticket_issue_time, ticket_issue_time);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Functional test: The TLS1.3 client can deserialize what it serializes with early data */
        {
            const uint32_t test_max_early_data_size = 100;
            const uint8_t test_early_data_context[] = "test context";
            const uint8_t test_app_protocol[] = "test protocol";
            const uint8_t test_app_protocol_len = strlen((const char *)test_app_protocol);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, test_max_early_data_size));
            EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn, test_early_data_context, sizeof(test_early_data_context)));
            EXPECT_MEMCPY_SUCCESS(conn->application_protocol, test_app_protocol, sizeof(test_app_protocol));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            /* Initialize client ticket */
            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = TICKET_AGE_ADD, .session_secret = test_session_secret };
            uint8_t client_ticket[] = { CLIENT_TICKET };
            EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, sizeof(client_ticket)));
            EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, client_ticket, sizeof(client_ticket));

            EXPECT_OK(s2n_serialize_resumption_state(conn, &ticket_fields, &stuffer));
            EXPECT_OK(s2n_deserialize_resumption_state(conn, &conn->client_ticket, &stuffer));

            /* Check PSK values are correct */
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);

            EXPECT_EQUAL(psk->early_data_config.protocol_version, S2N_TLS13);
            EXPECT_EQUAL(psk->early_data_config.max_early_data_size, test_max_early_data_size);
            EXPECT_EQUAL(psk->early_data_config.cipher_suite, &s2n_tls13_aes_256_gcm_sha384);
            EXPECT_EQUAL(psk->early_data_config.application_protocol.size, test_app_protocol_len);
            EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.application_protocol.data, test_app_protocol, test_app_protocol_len);
            EXPECT_EQUAL(psk->early_data_config.context.size, sizeof(test_early_data_context));
            EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.context.data, test_early_data_context, sizeof(test_early_data_context));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Functional test: Both TLS1.2 client and server can deserialize what they serialize */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, mock_time, NULL));

            for (s2n_mode mode = S2N_SERVER; mode <= S2N_CLIENT; mode++) {
                struct s2n_connection *conn = s2n_connection_new(mode);
                EXPECT_NOT_NULL(conn);
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure.cipher_suite = &s2n_rsa_with_aes_128_gcm_sha256;

                uint8_t s_data[S2N_TLS12_STATE_SIZE_IN_BYTES] = { 0 };
                struct s2n_blob state_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
                struct s2n_stuffer stuffer = { 0 };

                EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &state_blob));

                EXPECT_OK(s2n_serialize_resumption_state(conn, NULL, &stuffer));
                EXPECT_OK(s2n_deserialize_resumption_state(conn, NULL, &stuffer));

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* s2n_validate_ticket_age */
    {
        /* Ticket issue time is in the future */
        {
            uint64_t current_time = SECONDS_TO_NANOS(0);
            uint64_t issue_time = 10;
            EXPECT_ERROR_WITH_ERRNO(s2n_validate_ticket_age(current_time, issue_time), S2N_ERR_INVALID_SESSION_TICKET);
        }

        /** Ticket age is longer than a week
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *= type=test
         *# Clients MUST NOT cache
         *# tickets for longer than 7 days, regardless of the ticket_lifetime,
         *# and MAY delete tickets earlier based on local policy.
         */
        {
            uint64_t current_time = SECONDS_TO_NANOS(ONE_WEEK_IN_SEC + 1);
            uint64_t issue_time = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_validate_ticket_age(current_time, issue_time), S2N_ERR_INVALID_SESSION_TICKET);
        }

        /* Ticket age is a exactly a week */
        {
            uint64_t current_time = SECONDS_TO_NANOS(ONE_WEEK_IN_SEC);
            uint64_t issue_time = 0;
            EXPECT_OK(s2n_validate_ticket_age(current_time, issue_time));
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

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->client_ticket_to_decrypt), 0);

            /* Check decryption was successful by comparing master key */
            EXPECT_BYTEARRAY_EQUAL(conn->secure.master_secret, test_master_secret.data, test_master_secret.size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Check session ticket can be decrypted with a small secret in TLS13 session resumption. */
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
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_session_secret };

            /* This secret is smaller than the maximum secret length */
            EXPECT_TRUE(ticket_fields.session_secret.size < S2N_TLS_SECRET_LEN);

            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket_fields, &output));
            conn->client_ticket_to_decrypt = output;
            EXPECT_SUCCESS(s2n_decrypt_session_ticket(conn));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->client_ticket_to_decrypt), 0);

            /* Check decryption was successful */
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);
            EXPECT_EQUAL(psk->hmac_alg, s2n_tls13_aes_128_gcm_sha256.prf_alg);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Check session ticket can be decrypted with the maximum size secret in TLS13 session resumption. */
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
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_master_secret };

            /* This secret is equal to the maximum secret length */
            EXPECT_EQUAL(ticket_fields.session_secret.size, S2N_TLS_SECRET_LEN);

            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket_fields, &output));
            conn->client_ticket_to_decrypt = output;
            EXPECT_SUCCESS(s2n_decrypt_session_ticket(conn));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->client_ticket_to_decrypt), 0);

            /* Check decryption was successful */
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);
            EXPECT_EQUAL(psk->hmac_alg, s2n_tls13_aes_128_gcm_sha256.prf_alg);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Check session ticket is correct when using early data with TLS1.3. */
        {
            const uint8_t test_early_data_context[] = "context";
            const char test_app_proto[] = "https";

            /* Setting up session resumption encryption key */
            uint64_t current_time = 0;
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                         ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, 10));
            EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn, test_early_data_context, sizeof(test_early_data_context)));
            EXPECT_MEMCPY_SUCCESS(conn->application_protocol, test_app_proto, sizeof(test_app_proto));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            struct s2n_ticket_fields ticket_fields = { .ticket_age_add = 1, .session_secret = test_master_secret };

            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket_fields, &output));
            conn->client_ticket_to_decrypt = output;
            EXPECT_SUCCESS(s2n_decrypt_session_ticket(conn));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->client_ticket_to_decrypt), 0);

            /* Check decryption was successful */
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
            EXPECT_NOT_NULL(psk);
            EXPECT_EQUAL(psk->early_data_config.cipher_suite, &s2n_tls13_aes_128_gcm_sha256);

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
