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
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
/* To test static functions */
#include "tls/s2n_server_new_session_ticket.c"

#define TEST_TICKET_AGE_ADD 0x01, 0x02, 0x03, 0x04
#define TEST_LIFETIME       0x00, 0x01, 0x01, 0x01
#define TEST_TICKET         0x01, 0xFF, 0x23

#define ONE_HOUR_IN_NANOS 3600000000000

#define TICKET_AGE_ADD_MARKER sizeof(uint8_t) + /* message id  */ \
        SIZEOF_UINT24 +                         /* message len */ \
        sizeof(uint32_t)                        /* ticket lifetime */
#define RECORD_LEN_MARKER sizeof(uint8_t) +     /* message type */ \
        sizeof(uint16_t)                        /* protocol version */

#define MAX_TEST_SESSION_SIZE 300

#define EXPECT_TICKETS_SENT(conn, count) EXPECT_OK(s2n_assert_tickets_sent(conn, count))

static S2N_RESULT s2n_assert_tickets_sent(struct s2n_connection *conn, uint16_t expected_tickets_sent)
{
    uint16_t tickets_sent = 0;
    RESULT_GUARD_POSIX(s2n_connection_get_tickets_sent(conn, &tickets_sent));
    RESULT_ENSURE_EQ(tickets_sent, expected_tickets_sent);
    return S2N_RESULT_OK;
}

size_t cb_session_data_len = 0;
uint8_t cb_session_data[MAX_TEST_SESSION_SIZE] = { 0 };
uint32_t cb_session_lifetime = 0;
static int s2n_test_session_ticket_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(ticket);

    EXPECT_SUCCESS(s2n_session_ticket_get_data_len(ticket, &cb_session_data_len));
    EXPECT_SUCCESS(s2n_session_ticket_get_data(ticket, cb_session_data_len, cb_session_data));
    EXPECT_SUCCESS(s2n_session_ticket_get_lifetime(ticket, &cb_session_lifetime));

    return S2N_SUCCESS;
}

static int s2n_setup_test_ticket_key(struct s2n_config *config)
{
    POSIX_ENSURE_REF(config);

    /**
     *= https://tools.ietf.org/rfc/rfc5869#appendix-A.1
     *# PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *#        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     **/
    S2N_BLOB_FROM_HEX(ticket_key,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5");

    /* Set up encryption key */
    uint64_t current_time;
    uint8_t ticket_key_name[16] = "2016.07.26.15\0";
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
            ticket_key.data, ticket_key.size, current_time / ONE_SEC_IN_NANOS));

    return S2N_SUCCESS;
}

static int s2n_setup_test_resumption_secret(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    /**
     *= https://tools.ietf.org/rfc/rfc8448#section-3
     *# PRK (32 octets):  7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
     *# da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
     **/
    S2N_BLOB_FROM_HEX(test_resumption_secret,
            "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf \
             da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c");

    /* Set up resumption secret */
    struct s2n_blob secret = { 0 };
    struct s2n_stuffer secret_stuffer = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&secret, conn->secrets.version.tls13.resumption_master_secret, S2N_TLS_SECRET_LEN));
    EXPECT_SUCCESS(s2n_stuffer_init(&secret_stuffer, &secret));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&secret_stuffer, test_resumption_secret.data, test_resumption_secret.size));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_tls13_server_nst_write */
    {
        /* Check session ticket message is correctly written. */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            uint16_t test_tickets_sent = 10;
            conn->tickets_sent = test_tickets_sent;

            /* Set up output stuffer */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_OK(s2n_tls13_server_nst_write(conn, &output));

            uint8_t message_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &message_type));
            EXPECT_EQUAL(TLS_SERVER_NEW_SESSION_TICKET, message_type);

            uint32_t message_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint24(&output, &message_size));
            EXPECT_EQUAL(message_size, s2n_stuffer_data_available(&output));

            uint32_t ticket_lifetime = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &ticket_lifetime));
            uint32_t key_lifetime_in_secs =
                    (S2N_TICKET_ENCRYPT_DECRYPT_KEY_LIFETIME_IN_NANOS + S2N_TICKET_DECRYPT_KEY_LIFETIME_IN_NANOS) / ONE_SEC_IN_NANOS;
            EXPECT_EQUAL(key_lifetime_in_secs, ticket_lifetime);

            /* Skipping random data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, sizeof(uint32_t)));

            uint8_t ticket_nonce_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &ticket_nonce_len));
            EXPECT_EQUAL(sizeof(uint16_t), ticket_nonce_len);

            uint8_t ticket_nonce[sizeof(uint16_t)] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, ticket_nonce, ticket_nonce_len));

            uint8_t tickets_sent_array[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, tickets_sent_array, sizeof(uint16_t)));
            EXPECT_OK(s2n_generate_ticket_nonce(test_tickets_sent, &blob));
            EXPECT_BYTEARRAY_EQUAL(ticket_nonce, blob.data, ticket_nonce_len);

            uint16_t session_ticket_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &session_ticket_len));
            uint8_t size_of_extensions_size = sizeof(uint16_t);
            EXPECT_EQUAL(session_ticket_len, (s2n_stuffer_data_available(&output) - size_of_extensions_size));

            /* Skipping encrypted ticket data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, session_ticket_len));

            uint16_t extensions_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &extensions_len));
            EXPECT_EQUAL(extensions_len, 0);

            EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);

            EXPECT_TRUE(conn->tickets_sent == test_tickets_sent + 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* tickets_sent overflow */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->tickets_sent = UINT16_MAX;

            /* Set up output stuffer */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_server_nst_write(conn, &output), S2N_ERR_INTEGER_OVERFLOW);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /** ticket_age_add values do not repeat after sending multiple new session tickets
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *= type=test
         *#  The server MUST generate a fresh value
         *#  for each ticket it sends.
         **/
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            /* Set up output stuffer */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_OK(s2n_tls13_server_nst_write(conn, &output));

            uint32_t original_ticket_age_add = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, TICKET_AGE_ADD_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &original_ticket_age_add));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&output));
            EXPECT_OK(s2n_tls13_server_nst_write(conn, &output));

            uint32_t new_ticket_age_add = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, TICKET_AGE_ADD_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &new_ticket_age_add));

            EXPECT_NOT_EQUAL(original_ticket_age_add, new_ticket_age_add);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Test that the message written by the server includes extensions.
         * Specifically, check for the early_data_indication extension. */
        {
            const uint32_t expected_max_early_data_size = 10;

            /* Calculate extension list offset. Extension list should be last. */
            const uint32_t extension_list_offset = sizeof(uint32_t) /* max_early_data_size */
                    + sizeof(uint16_t)                              /* size of extension */
                    + sizeof(uint16_t);                             /* type of extension */

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, expected_max_early_data_size));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_OK(s2n_tls13_server_nst_write(conn, &output));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output,
                    s2n_stuffer_data_available(&output) - extension_list_offset));

            uint16_t extension_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &extension_type));
            EXPECT_EQUAL(extension_type, TLS_EXTENSION_EARLY_DATA);

            uint16_t extension_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &extension_size));
            EXPECT_EQUAL(extension_size, sizeof(uint32_t));

            uint32_t actual_max_early_data_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &actual_max_early_data_size));
            EXPECT_EQUAL(actual_max_early_data_size, expected_max_early_data_size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Can't write ticket larger than allowed size of a PSK identity */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, 10));

            /* Set context to be UINT16_MAX */
            uint8_t early_data_context[UINT16_MAX] = { 0 };
            EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(server_conn,
                    early_data_context, sizeof(early_data_context)));

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_server_nst_write(server_conn, &stuffer), S2N_ERR_SIZE_MISMATCH);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* s2n_generate_ticket_lifetime */
    {
        uint32_t min_lifetime = 0;
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Test: encrypt + decrypt key has shortest lifetime */
        conn->config->encrypt_decrypt_key_lifetime_in_nanos = ONE_HOUR_IN_NANOS;
        conn->config->decrypt_key_lifetime_in_nanos = ONE_HOUR_IN_NANOS;
        conn->config->session_state_lifetime_in_nanos = ONE_HOUR_IN_NANOS * 3;

        EXPECT_OK(s2n_generate_ticket_lifetime(conn, &min_lifetime));
        EXPECT_EQUAL(min_lifetime, (ONE_HOUR_IN_NANOS * 2) / ONE_SEC_IN_NANOS);

        /* Test: Session state has shortest lifetime */
        conn->config->encrypt_decrypt_key_lifetime_in_nanos = ONE_HOUR_IN_NANOS;
        conn->config->decrypt_key_lifetime_in_nanos = ONE_HOUR_IN_NANOS;
        conn->config->session_state_lifetime_in_nanos = ONE_HOUR_IN_NANOS;

        EXPECT_OK(s2n_generate_ticket_lifetime(conn, &min_lifetime));
        EXPECT_EQUAL(min_lifetime, ONE_HOUR_IN_NANOS / ONE_SEC_IN_NANOS);

        /** Test: Both session state and decrypt key have longer lifetimes than a week
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *= type=test
         *# Servers MUST NOT use any value greater than
         *# 604800 seconds (7 days).
         **/
        /* Note: We turn these integer literals into uint64_t values because otherwise
         * they will be interpreted as uint32_t values and an faulty integer overflow error
         * will be thrown. */
        uint64_t one_week_in_sec = ONE_WEEK_IN_SEC;
        uint64_t one_sec_in_nanos = ONE_SEC_IN_NANOS;
        uint64_t one_week_in_nanos = one_week_in_sec * one_sec_in_nanos;
        conn->config->encrypt_decrypt_key_lifetime_in_nanos = one_week_in_nanos;
        conn->config->decrypt_key_lifetime_in_nanos = one_week_in_nanos;
        conn->config->session_state_lifetime_in_nanos = one_week_in_nanos + 1;

        EXPECT_OK(s2n_generate_ticket_lifetime(conn, &min_lifetime));
        EXPECT_EQUAL(min_lifetime, ONE_WEEK_IN_SEC);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_generate_ticket_nonce */
    {
        struct {
            uint16_t value;
            uint8_t expected_output[2];
        } test_cases[] = {
            { .value = 0, .expected_output = { 0, 0 } },
            { .value = 1, .expected_output = { 0, 1 } },
            { .value = 20, .expected_output = { 0, 20 } },
            { .value = UINT8_MAX, .expected_output = { 0, UINT8_MAX } },
            { .value = UINT8_MAX + 1, .expected_output = { 1, 0 } },
            { .value = UINT16_MAX, .expected_output = { UINT8_MAX, UINT8_MAX } },
            { .value = UINT16_MAX - 1, .expected_output = { UINT8_MAX, UINT8_MAX - 1 } },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            uint8_t data[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));

            EXPECT_OK(s2n_generate_ticket_nonce(test_cases[i].value, &blob));

            EXPECT_EQUAL(test_cases[i].expected_output[0], data[0]);
            EXPECT_EQUAL(test_cases[i].expected_output[1], data[1]);
        }
    };

    /* s2n_generate_ticket_age_add */
    {
        struct {
            uint8_t value[4];
            uint32_t expected_output;
        } test_cases[] = {
            { .value = { 0, 0, 0, 0 }, .expected_output = 0 },
            { .value = { 0, 0, 0, 1 }, .expected_output = 1 },
            { .value = { 0, 0, 0, 20 }, .expected_output = 20 },
            { .value = { 0, 0, 1, 0 }, .expected_output = UINT8_MAX + 1 },
            { .value = { 0, 1, 0, 0 }, .expected_output = UINT16_MAX + 1 },
            { .value = { 0, 0, UINT8_MAX, UINT8_MAX }, .expected_output = UINT16_MAX },
            { .value = { UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX }, .expected_output = UINT32_MAX },
            { .value = { UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX - 1 }, .expected_output = UINT32_MAX - 1 },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            uint32_t output = 0;
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, test_cases[i].value, sizeof(test_cases[i].value)));
            EXPECT_OK(s2n_generate_ticket_age_add(&blob, &output));

            EXPECT_EQUAL(output, test_cases[i].expected_output);
        }
    };

    /* s2n_generate_session_secret */
    {
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *# expanded (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c
         *# a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         **/
        /* clang-format off */
        S2N_BLOB_FROM_HEX(expected_session_secret,
                       "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c \
            a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");
        /* clang-format on */

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        EXPECT_SUCCESS(s2n_setup_test_resumption_secret(conn));

        uint8_t nonce_data[sizeof(uint16_t)] = { 0 };
        struct s2n_blob nonce = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&nonce, nonce_data, sizeof(nonce_data)));

        struct s2n_blob *output = &conn->tls13_ticket_fields.session_secret;
        EXPECT_SUCCESS(s2n_generate_session_secret(conn, &nonce, output));
        EXPECT_EQUAL(output->size, expected_session_secret.size);
        EXPECT_BYTEARRAY_EQUAL(output->data, expected_session_secret.data, expected_session_secret.size);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_tls13_server_nst_recv */
    {
        uint8_t test_ticket[] = { TEST_TICKET };
        uint8_t nst_data[] = {
            TEST_LIFETIME,       /* ticket lifetime */
            TEST_TICKET_AGE_ADD, /* ticket age add */
            0x02,                /* nonce len */
            0x00, 0x00,          /* nonce */
            0x00, 0x03,          /* ticket len */
            TEST_TICKET,         /* ticket */
            0x00, 0x00,          /* extensions len */
        };

        /* Does not read ticket message if config->use_tickets is not set */
        {
            struct s2n_config *config = s2n_config_new();
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_NOT_NULL(config);

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set up input stuffer */
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_blob nst_message = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&nst_message, nst_data, sizeof(nst_data)));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &nst_message));

            EXPECT_OK(s2n_tls13_server_nst_recv(conn, &input));

            EXPECT_EQUAL(conn->client_ticket.size, 0);
            EXPECT_TRUE(s2n_stuffer_data_available(&input) > 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Not allowed in TLS1.2 */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            /* Set up input stuffer */
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_blob nst_message = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&nst_message, nst_data, sizeof(nst_data)));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &nst_message));

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_server_nst_recv(conn, &input), S2N_ERR_BAD_MESSAGE);

            EXPECT_EQUAL(conn->client_ticket.size, 0);
            EXPECT_TRUE(s2n_stuffer_data_available(&input) > 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Tests session_ticket_cb correctly serializes session data from an arbitrary new session ticket message */
        {
            struct s2n_config *config = s2n_config_new();
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_NOT_NULL(config);

            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            /* Set up input stuffer */
            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_blob nst_message = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&nst_message, nst_data, sizeof(nst_data)));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &nst_message));

            EXPECT_OK(s2n_tls13_server_nst_recv(conn, &input));
            EXPECT_BYTEARRAY_EQUAL(conn->client_ticket.data, test_ticket, sizeof(test_ticket));
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), 0);

            /* Initialize a stuffer to examine the serialized data returned in the session ticket callback */
            struct s2n_blob session_blob = { 0 };
            struct s2n_stuffer session_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&session_blob, cb_session_data, cb_session_data_len));
            EXPECT_SUCCESS(s2n_stuffer_init(&session_stuffer, &session_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&session_stuffer, cb_session_data_len));

            /* Check the serialized ticket is what was in the arbitrary nst message */
            {
                /* Skip to encrypted ticket size */
                EXPECT_SUCCESS((s2n_stuffer_skip_read(&session_stuffer, sizeof(uint8_t))));

                uint16_t ticket_size = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&session_stuffer, &ticket_size));
                EXPECT_EQUAL(ticket_size, sizeof(test_ticket));

                uint8_t *ticket = s2n_stuffer_raw_read(&session_stuffer, ticket_size);
                EXPECT_NOT_NULL(ticket);
                EXPECT_BYTEARRAY_EQUAL(ticket, test_ticket, ticket_size);
            };

            /* Check the serialized ticket_age_add is what was in the arbitrary nst message */
            {
                uint8_t test_ticket_age_add[] = { TEST_TICKET_AGE_ADD };
                uint8_t ticket_age_add_marker = sizeof(uint8_t) + /* client state format */
                        sizeof(uint8_t) +                         /* protocol version */
                        sizeof(uint16_t) +                        /* cipher suite */
                        sizeof(uint64_t);                         /* time */
                /* Skip to ticket_age_add */
                EXPECT_SUCCESS((s2n_stuffer_skip_read(&session_stuffer, ticket_age_add_marker)));

                uint8_t ticket_age_add[sizeof(uint32_t)] = { 0 };
                EXPECT_SUCCESS(s2n_stuffer_read_bytes(&session_stuffer, ticket_age_add, sizeof(uint32_t)));
                EXPECT_BYTEARRAY_EQUAL(ticket_age_add, test_ticket_age_add, sizeof(uint32_t));
            };

            /* Check ticket lifetime is what was in the arbitrary nst message */
            {
                uint8_t test_lifetime[] = { TEST_LIFETIME };
                uint32_t expected_lifetime = test_lifetime[3] | (test_lifetime[2] << 8) | (test_lifetime[1] << 16) | (test_lifetime[0] << 24);
                EXPECT_EQUAL(expected_lifetime, cb_session_lifetime);
            };
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Known values test */
        {
            /**
             * NewSessionTicket handshake message
             * 
             *= https://tools.ietf.org/rfc/rfc8448#section-3
             *# NewSessionTicket (205 octets):  04 00 00 c9 00 00 00 1e fa d6 aa
             *#    c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
             *#    00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c
             *#    49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
             *#    72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28
             *#    27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25
             *#    a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c
             *#    5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6
             *#    17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50
             *#    5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
             *#    04 00 00 04 00
             **/
            /* clang-format off */
            S2N_BLOB_FROM_HEX(nst_message,
                                             "04 00 00 c9 00 00 00 1e fa d6 aa \
                c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00 \
                00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c \
                49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11 \
                72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28 \
                27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25 \
                a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c \
                5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 \
                17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 \
                5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00 \
                04 00 00 04 00");
            /* clang-format on */

            struct s2n_config *config = s2n_config_new();
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_NOT_NULL(config);

            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            /* Set up input stuffer */
            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &nst_message));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&input, sizeof(uint8_t) + SIZEOF_UINT24));
            EXPECT_OK(s2n_tls13_server_nst_recv(conn, &input));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Self-talk test */
        {
            struct s2n_config *config = s2n_config_new();
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_NOT_NULL(config);

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            client_conn->actual_protocol_version = S2N_TLS13;
            server_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_OK(s2n_tls13_server_nst_write(server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, sizeof(uint8_t) + SIZEOF_UINT24));
            EXPECT_OK(s2n_tls13_server_nst_recv(client_conn, &stuffer));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test that the client processes extensions.
         * Specifically, check for the early_data_indication extension. */
        {
            const uint32_t expected_max_early_data_size = 17;

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, expected_max_early_data_size));

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_EQUAL(client_conn->server_max_early_data_size, 0);
            EXPECT_OK(s2n_tls13_server_nst_write(server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, sizeof(uint8_t) + SIZEOF_UINT24));
            EXPECT_OK(s2n_tls13_server_nst_recv(client_conn, &stuffer));
            EXPECT_EQUAL(client_conn->server_max_early_data_size, expected_max_early_data_size);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test that the client can handle different max_early_data_size values. */
        {
            const uint32_t expected_max_early_data_sizes[] = { 17, 0, UINT16_MAX, 0, 20, UINT32_MAX, 5, 0 };

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            for (size_t i = 0; i < s2n_array_len(expected_max_early_data_sizes); i++) {
                EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, expected_max_early_data_sizes[i]));
                EXPECT_OK(s2n_tls13_server_nst_write(server_conn, &stuffer));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, sizeof(uint8_t) + SIZEOF_UINT24));
                EXPECT_OK(s2n_tls13_server_nst_recv(client_conn, &stuffer));
                EXPECT_EQUAL(client_conn->server_max_early_data_size, expected_max_early_data_sizes[i]);
                EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
            }

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test that the client rejects tickets with invalid ticket_lifetime */
        {
            const size_t lifetime_size = sizeof(uint32_t);
            const uint8_t *nst_data_without_lifetime = nst_data + lifetime_size;
            const size_t nst_data_without_lifetime_size = sizeof(nst_data) - lifetime_size;

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));

            /**
             *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
             *= type=test
             *# The value of zero indicates that the
             *# ticket should be discarded immediately.
             */
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                conn->actual_protocol_version = S2N_TLS13;

                DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, sizeof(nst_data)));
                EXPECT_SUCCESS(s2n_stuffer_write_uint32(&input, 0));
                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, nst_data_without_lifetime, nst_data_without_lifetime_size));

                EXPECT_OK(s2n_tls13_server_nst_recv(conn, &input));
                /* Verify that the client only got as far as the ticket_lifetime when parsing */
                EXPECT_EQUAL(s2n_stuffer_data_available(&input), nst_data_without_lifetime_size);
                /* Verify that the client did not accept + store the ticket */
                EXPECT_EQUAL(s2n_connection_get_session_length(conn), 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /**
             *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
             *= type=test
             *# Servers MUST NOT use any value greater than
             *# 604800 seconds (7 days).
             */
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                conn->actual_protocol_version = S2N_TLS13;

                DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, sizeof(nst_data)));
                EXPECT_SUCCESS(s2n_stuffer_write_uint32(&input, UINT32_MAX));
                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, nst_data_without_lifetime, nst_data_without_lifetime_size));

                EXPECT_ERROR_WITH_ERRNO(s2n_tls13_server_nst_recv(conn, &input), S2N_ERR_BAD_MESSAGE);
                /* Verify that the client only got as far as the ticket_lifetime when parsing */
                EXPECT_EQUAL(s2n_stuffer_data_available(&input), nst_data_without_lifetime_size);
                /* Verify that the client did not accept + store the ticket */
                EXPECT_EQUAL(s2n_connection_get_session_length(conn), 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* s2n_tls13_server_nst_send */
    {
        /* Mode is not server */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->actual_protocol_version = S2N_TLS13;
            conn->tickets_to_send = 1;

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            EXPECT_ERROR_WITH_ERRNO(s2n_assert_tickets_sent(conn, 0), S2N_ERR_CLIENT_MODE);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Protocol is less than TLS13 */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->tickets_to_send = 1;

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_ERROR(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 0);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 1);
        };

        /* 0 tickets are requested */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS13;
            conn->tickets_to_send = 0;
            EXPECT_NOT_EQUAL(0, s2n_stuffer_space_remaining(&conn->handshake.io));

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            /* Check no tickets are written */
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            EXPECT_TICKETS_SENT(conn, 0);

            /* Check handshake.io is cleaned up */
            EXPECT_EQUAL(0, s2n_stuffer_space_remaining(&conn->handshake.io));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* QUIC mode is enabled */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->tickets_to_send = 1;
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;

            conn->quic_enabled = true;
            /* No mutually-supported psk mode agreed upon */
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 0);

            /* Client has indicated that it supports both resumption and psk_dhe_ke mode */
            conn->psk_params.psk_ke_mode = S2N_PSK_DHE_KE;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 1);
        };

        /* Sends one new session ticket */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->tickets_to_send = 1;
            EXPECT_NOT_EQUAL(s2n_stuffer_space_remaining(&conn->handshake.io), 0);

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 1);

            /* Check only one record was written */
            uint16_t record_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, RECORD_LEN_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &record_len));
            EXPECT_TRUE(record_len > 0);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, record_len));
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Send no more tickets if keying material is expired
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *= type=test
         *# Note that in principle it is possible to continue issuing new tickets
         *# which indefinitely extend the lifetime of the keying material
         *# originally derived from an initial non-PSK handshake (which was most
         *# likely tied to the peer's certificate). It is RECOMMENDED that
         *# implementations place limits on the total lifetime of such keying
         *# material; these limits should take into account the lifetime of the
         *# peer's certificate, the likelihood of intervening revocation, and the
         *# time since the peer's online CertificateVerify signature.
         */
        {
            const uint8_t current_tickets = 10;
            const uint8_t new_tickets = 5;

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS13;
            conn->tickets_sent = current_tickets;
            conn->tickets_to_send = current_tickets;
            EXPECT_TICKETS_SENT(conn, current_tickets);

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            /* Can request new tickets */
            EXPECT_SUCCESS(s2n_connection_add_new_tickets_to_send(conn, new_tickets));
            EXPECT_EQUAL(conn->tickets_sent, current_tickets);
            EXPECT_EQUAL(conn->tickets_to_send, current_tickets + new_tickets);
            EXPECT_TICKETS_SENT(conn, current_tickets);

            /* Add expired keying material */
            DEFER_CLEANUP(struct s2n_psk *chosen_psk = s2n_test_psk_new(conn), s2n_psk_free);
            EXPECT_NOT_NULL(chosen_psk);
            chosen_psk->type = S2N_PSK_TYPE_RESUMPTION;
            chosen_psk->keying_material_expiration = 0;
            conn->psk_params.chosen_psk = chosen_psk;

            /* Despite tickets requested, no tickets sent */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
            EXPECT_EQUAL(conn->tickets_sent, current_tickets);
            EXPECT_EQUAL(conn->tickets_to_send, current_tickets);
            EXPECT_TICKETS_SENT(conn, current_tickets);

            /* Can't request more tickets */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_add_new_tickets_to_send(conn, new_tickets),
                    S2N_ERR_KEYING_MATERIAL_EXPIRED);
            EXPECT_EQUAL(conn->tickets_sent, current_tickets);
            EXPECT_EQUAL(conn->tickets_to_send, current_tickets);
            EXPECT_TICKETS_SENT(conn, current_tickets);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* s2n_config_set_session_tickets_onoff used to enable tickets */
        {
            uint8_t test_data[S2N_TICKET_KEY_NAME_LEN] = "data";
            uint64_t current_time = 0;

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, test_data, sizeof(test_data),
                    test_data, sizeof(test_data), current_time / ONE_SEC_IN_NANOS));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 1);
            EXPECT_NOT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

            /* Request more tickets */
            EXPECT_SUCCESS(s2n_connection_add_new_tickets_to_send(conn, 1));
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 2);
            EXPECT_NOT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

            /* Turn tickets off */
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, false));

            /* Request more tickets */
            EXPECT_SUCCESS(s2n_connection_add_new_tickets_to_send(conn, 1));
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 2);
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* s2n_config_set_initial_ticket_count used to enable tickets */
        {
            uint8_t test_data[S2N_TICKET_KEY_NAME_LEN] = "data";
            uint64_t current_time = 0;

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_initial_ticket_count(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, test_data, sizeof(test_data),
                    test_data, sizeof(test_data), current_time / ONE_SEC_IN_NANOS));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, 1);
            EXPECT_NOT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Sends multiple new session tickets */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            uint16_t tickets_to_send = 5;
            conn->tickets_to_send = tickets_to_send;

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_TICKETS_SENT(conn, tickets_to_send);

            /* Check five records were written */
            uint16_t record_len = 0;
            for (size_t i = 0; i < tickets_to_send; i++) {
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, RECORD_LEN_MARKER));
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &record_len));
                EXPECT_TRUE(record_len > 0);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, record_len));
            }
            EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) == 0);

            /* No more tickets to send */
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Test S2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* TLS1.3 tickets contain extra fields */
            conn->actual_protocol_version = S2N_TLS13;
            /* Largest possible TLS1.3 secret size */
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            /* Necessary for extensions, which contribute to size */
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, 10));

            /* Setup io */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &output, conn));

            /* Test with no variable fields */
            {
                size_t session_state_size = 0;
                EXPECT_OK(s2n_connection_get_session_state_size(conn, &session_state_size));
                EXPECT_NOT_EQUAL(session_state_size, 0);

                s2n_blocked_status blocked = 0;
                EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
                EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&output), 0);

                uint32_t expected_max_size = s2n_stuffer_data_available(&output) - S2N_TLS_RECORD_HEADER_LENGTH;
                uint32_t expected_max_fixed_size = expected_max_size - session_state_size;
                if (S2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE != expected_max_fixed_size) {
                    fprintf(stdout, "\nS2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE (%i) should be %u\n",
                            (int) S2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE, expected_max_fixed_size);
                }
                EXPECT_EQUAL(S2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE, expected_max_fixed_size);
            };

            EXPECT_SUCCESS(s2n_stuffer_wipe(&output));
            conn->tickets_to_send++;

            /* Test with some variable fields */
            {
                const uint8_t early_data_context[] = "early data context";
                EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn,
                        early_data_context, sizeof(early_data_context)));

                size_t session_state_size = 0;
                EXPECT_OK(s2n_connection_get_session_state_size(conn, &session_state_size));
                EXPECT_NOT_EQUAL(session_state_size, 0);

                s2n_blocked_status blocked = 0;
                EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
                EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&output), 0);

                uint32_t expected_max_size = s2n_stuffer_data_available(&output) - S2N_TLS_RECORD_HEADER_LENGTH;
                uint32_t expected_max_fixed_size = expected_max_size - session_state_size;
                EXPECT_EQUAL(S2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE, expected_max_fixed_size);
            };

            EXPECT_SUCCESS(s2n_stuffer_wipe(&output));
            conn->tickets_to_send++;

            /* Test with all variable fields */
            {
                const uint8_t early_data_context[] = "different early data context";
                EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn,
                        early_data_context, sizeof(early_data_context)));

                const uint8_t app_protocol[] = "https";
                EXPECT_MEMCPY_SUCCESS(conn->application_protocol, app_protocol, sizeof(app_protocol));

                size_t session_state_size = 0;
                EXPECT_OK(s2n_connection_get_session_state_size(conn, &session_state_size));
                EXPECT_NOT_EQUAL(session_state_size, 0);

                s2n_blocked_status blocked = 0;
                EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
                EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&output), 0);

                uint32_t expected_max_size = s2n_stuffer_data_available(&output) - S2N_TLS_RECORD_HEADER_LENGTH;
                uint32_t expected_max_fixed_size = expected_max_size - session_state_size;
                EXPECT_EQUAL(S2N_TLS13_MAX_FIXED_NEW_SESSION_TICKET_SIZE, expected_max_fixed_size);
            };

            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* Functional test: s2n_negotiate sends new session tickets after the handshake is complete */
    if (s2n_is_tls13_fully_supported()) {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint16_t tickets_to_send = 5;
        server_conn->tickets_to_send = tickets_to_send;

        struct s2n_stuffer client_to_server = { 0 };
        struct s2n_stuffer server_to_client = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        /* Do handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TICKETS_SENT(server_conn, tickets_to_send);

        /* Check handshake.io was cleaned up.
         * If a ticket was written, this happens afterwards. */
        EXPECT_EQUAL(s2n_stuffer_space_remaining(&server_conn->handshake.io), 0);
        EXPECT_EQUAL(s2n_stuffer_space_remaining(&client_conn->handshake.io), 0);

        /* Check there are five records corresponding to five new session tickets
         * not read as part of the handshake */
        uint16_t record_len = 0;
        for (size_t i = 0; i < tickets_to_send; i++) {
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&server_to_client, RECORD_LEN_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_to_client, &record_len));
            EXPECT_TRUE(record_len > 0);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&server_to_client, record_len));
        }
        EXPECT_TRUE(s2n_stuffer_data_available(&server_to_client) == 0);

        /* Call s2n_negotiate again to ensure no more tickets are sent */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(0, s2n_stuffer_data_available(&server_to_client));
        EXPECT_TICKETS_SENT(server_conn, tickets_to_send);

        EXPECT_SUCCESS(s2n_stuffer_free(&client_to_server));
        EXPECT_SUCCESS(s2n_stuffer_free(&server_to_client));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
