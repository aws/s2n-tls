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

#include "sys/param.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "api/s2n.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

/* How many bytes to trim off from a buffer when mocking a partial send. */
#define PARTIAL_SEND_TRIM 3

#define SMALL_CHUNK_SEND_SIZE (4096)
#define LARGE_SEND_SIZE (S2N_TLS_MAXIMUM_RECORD_LENGTH * 4)
/* VERY_LARGE_SEND_SIZE is 0.5 GB. */
#define VERY_LARGE_SEND_SIZE (1 << 29)

/* Buffer filled with an arbitrary string for testing. */
static uint8_t test_data[] = "hello world";

bool s2n_custom_send_fn_called = false;
static uint64_t sent_bytes = 0;

int s2n_expect_concurrent_error_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;

    s2n_blocked_status blocked = 0;
    ssize_t result = s2n_send(conn, buf, len, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

static int s2n_track_sent_bytes_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    (void) io_context;

    s2n_custom_send_fn_called = true;
    sent_bytes = len;

    return len;
}

/* Mock socket send that will set EPIPE on the second send. */
static int s2n_broken_pipe_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    (void) io_context;

    if (s2n_custom_send_fn_called) {
        errno = EPIPE;
        return -1;
    }

    s2n_custom_send_fn_called = true;
    int partial_send = len - PARTIAL_SEND_TRIM;
    sent_bytes = partial_send;

    return partial_send;
}

/* Mock send that will always do a successful full send. */
static int s2n_send_always_passes_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    s2n_custom_send_fn_called = true;
    return len;
}

/* Mock send to verify that s2n_send is mitigating the BEAST attack.
 * What we expect to see is a one byte sized record preceding normal send behavior. */
static int s2n_send_mitigates_beast_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;
    uint32_t *writes = (uint32_t*) s2n_connection_get_ctx(conn);

    /* The BEAST mitigation in s2n_send should first send a 1 byte record and then the rest of the application data. */
    uint32_t expected_write_sizes[] = {1, sizeof(test_data)};

    EXPECT_EQUAL(conn->current_user_data_consumed, expected_write_sizes[*writes]);

    *writes += 1;

    return len;
}

/* Mock send that verifies all sends are the same size as the max amount of bytes that fit in a single Ethernet frame. */
static int s2n_dynamic_record_sizing_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;
    uint32_t *writes = (uint32_t*) s2n_connection_get_ctx(conn);
    
    uint16_t single_eth_frame_record_size = 0;
    POSIX_GUARD_RESULT(s2n_record_min_write_payload_size(conn, &single_eth_frame_record_size));

    /* Until we hit the dynamic record resize threshold we expect that the total data sent in bytes is divisible
     * by the s2n_record_min_write_payload_size. Once the threshold is exceeded the feature is no longer active 
     * until the dynamic record resize timer is triggered.
     * 
     * Since the send is larger than the dynamic record resize threshold and the connection timer for the dynamic sizing
     * is in practice frozen for this test, we can control which writes use the dynamic record sizing. 
     *
     * We will expect that the first write and the third write are forced to use dynamic record sizing, so every
     * record fragment sent over the wire should be divisible by single_eth_frame_record_size.
     */
    if (conn->active_application_bytes_consumed <= conn->dynamic_record_resize_threshold) {
        /* The test is set up so dynamic record sizes are only used in the first and third writes. */
        EXPECT_TRUE(*writes == 1 || *writes == 3);
        EXPECT_EQUAL(conn->current_user_data_consumed % single_eth_frame_record_size, 0);
    }

    return len;
}

/* Mock send implementation that will return EAGAIN once a specified limit is hit. */
static int s2n_byte_limit_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;
    ssize_t *bytes_to_send = (ssize_t*) s2n_connection_get_ctx(conn);

    /* Cede control back to application when the bytes_to_send threshold is reached. */
    if (conn->current_user_data_consumed > *bytes_to_send) {
        errno = EAGAIN;
        return -1;
    }

    return len;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_blob large_data = {0}, s2n_free);
    /* Allocate 32KB so it takes multiple records to send complete data. */
    EXPECT_SUCCESS(s2n_alloc(&large_data, LARGE_SEND_SIZE));
    EXPECT_OK(s2n_get_public_random_data(&large_data));

    /* s2n_send cannot be called concurrently */
    {
        /* Setup connections */
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Setup bad send callback */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_expect_concurrent_error_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));
        /* Send test data */
        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(0, conn->wire_bytes_out);
    }

    /* s2n_send tracks conn->wire_bytes_out on send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        EXPECT_EQUAL(0, conn->wire_bytes_out);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_track_sent_bytes_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;

        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(sizeof(test_data), s2n_send(conn, test_data, sizeof(test_data), &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(sent_bytes, conn->wire_bytes_out);
        EXPECT_EQUAL(sent_bytes, s2n_connection_get_wire_bytes_out(conn));
        EXPECT_EQUAL(conn->wire_bytes_out, s2n_connection_get_wire_bytes_out(conn));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
    }

    /* s2n_send tracks conn->wire_bytes_out on partial send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        EXPECT_EQUAL(0, conn->wire_bytes_out);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_broken_pipe_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;

        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(sent_bytes, conn->wire_bytes_out);
        EXPECT_EQUAL(sent_bytes, s2n_connection_get_wire_bytes_out(conn));
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
    }

    /* s2n_flush will close a closing connection */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        s2n_blocked_status blocked = 0;

        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_FALSE(conn->closed);

        conn->closing = 1;
        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_TRUE(conn->closed);
    }

    /* s2n_flush will send the out stuffer before closing a connection */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));

        s2n_blocked_status blocked = 0;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&conn->out, sizeof(test_data)));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->out, test_data, sizeof(test_data)));

        s2n_custom_send_fn_called = false;
        conn->closing = 1;
        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_TRUE(conn->closed);
        EXPECT_TRUE(s2n_custom_send_fn_called);
    }

    /* s2n_flush will send any pending alerts and then close the socket if a reader or writer alert are buffered */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), 0);

        s2n_blocked_status blocked = 0;
        const uint8_t close_notify_alert[] = {  2 /* AlertLevel = fatal */,
                                                0 /* AlertDescription = close_notify */ };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->reader_alert_out, close_notify_alert, sizeof(close_notify_alert)));
        EXPECT_FALSE(conn->closed);
        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_TRUE(conn->closed);

        conn->closed = 0;
        conn->closing = 0;

        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->writer_alert_out, close_notify_alert, sizeof(close_notify_alert)));
        EXPECT_FALSE(conn->closed);
        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_TRUE(conn->closed);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
    }

    /* s2n_sendv_with_offset checks for a closed socket */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        conn->closed = 1;
        EXPECT_FAILURE_WITH_ERRNO(s2n_sendv_with_offset(conn, NULL, 0, 0, NULL), S2N_ERR_CLOSED);
    }

    /* s2n_sendv_with_offset mitigates the BEAST attack by writing a 1 byte record
     * before swapping to a "regular" send behavior, e.g. not 1 byte records. */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        uint32_t writes = 0;

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_mitigates_beast_fn));
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&writes));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;

        /* We need to initialize the client mac to make sure our encrypted data is larger than the CBC block size. */
        struct s2n_hmac_state *mock_mac_state = &conn->client->client_record_mac;
        EXPECT_SUCCESS(s2n_hmac_init(mock_mac_state, S2N_HMAC_SHA256, test_data, sizeof(test_data)));

        /* Tweak the connection object to enable the BEAST mitigation. 
         * Currently the conditions we need to hit to enable the BEAST mitigation are:
         * 1. actual_protocol_version < S2N_TLS11 
         * 2. connection is in client mode
         * 3. the chosen cipher uses CBC */
        conn->actual_protocol_version = S2N_TLS10;
        /* This can be any cipher suite that uses CBC. s2n_rsa_with_3des_ede_cbc_sha is chosen because it's easier to stub. */
        struct s2n_cipher_suite *cipher_suite = &s2n_rsa_with_3des_ede_cbc_sha;
        struct s2n_cipher_suite *composite_cipher_suite = &s2n_rsa_with_aes_128_cbc_sha;
        conn->client->cipher_suite = cipher_suite;

        /* We need to check out if a composite cipher is available to filter out BoringSSL and AWSLC, or s2n_send will fail trying to use CBC. */
        if (cipher_suite->available && composite_cipher_suite->all_record_algs[0]->cipher->is_available()) {
            s2n_custom_send_fn_called = false;
            EXPECT_SUCCESS(s2n_send(conn, test_data, sizeof(test_data), &blocked));
            EXPECT_TRUE(s2n_custom_send_fn_called);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        }
    }

    /* When dynamic records are enabled s2n_send will send the max sized record that fits in a single Ethernet frame
     * until the dyanmic record threshold is reached. */
    {
        uint32_t writes = 1;
        s2n_blocked_status blocked = 0;
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_dynamic_record_sizing_fn));
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&writes));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        uint16_t single_eth_frame_record_size = 0;
        POSIX_GUARD_RESULT(s2n_record_min_write_payload_size(conn, &single_eth_frame_record_size));

        /* We will use 16KB as our dynamic record threshold. This means we will try to send the max amount of bytes
         * we can in a single ethernet frame, until we have reached the 16KB of data sent or if the threshold timer expires. */
        uint32_t resize_threshold = S2N_TLS_MAXIMUM_RECORD_LENGTH;
        /* Choose a long time out so the first two calls to s2n_send do not reset the dynamic record size threshold. */
        uint16_t timeout_threshold_secs = UINT16_MAX;
        EXPECT_SUCCESS(s2n_connection_set_dynamic_record_threshold(conn, resize_threshold, timeout_threshold_secs));

        EXPECT_EQUAL(conn->last_write_elapsed, 0);
        EXPECT_EQUAL(conn->active_application_bytes_consumed, 0);
        uint64_t last_clock = conn->last_write_elapsed;

        EXPECT_SUCCESS(s2n_send(conn, large_data.data, large_data.size, &blocked)); 
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        /* Make sure the clock was sampled when dynamic record sizing is enabled. */
        EXPECT_NOT_EQUAL(conn->last_write_elapsed, last_clock);
        last_clock = conn->last_write_elapsed;

        EXPECT_EQUAL(conn->active_application_bytes_consumed, large_data.size);

        writes += 1;
        s2n_custom_send_fn_called = false;

        EXPECT_SUCCESS(s2n_send(conn, large_data.data, large_data.size, &blocked)); 
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        EXPECT_NOT_EQUAL(conn->last_write_elapsed, last_clock);

        /* The dynamic record timeout has not yet been hit so conn->active_application_bytes_consumed
         * should still contain the two full send lens. */
        EXPECT_EQUAL(conn->active_application_bytes_consumed, large_data.size * 2);

        writes += 1;

        /* Here we reset the clock and move the timeout threshold, forcing
         * conn->active_application_bytes_consumed to reset back to 0 byts. */
        conn->last_write_elapsed = 0;
        timeout_threshold_secs = 1;
        EXPECT_SUCCESS(s2n_connection_set_dynamic_record_threshold(conn, resize_threshold, timeout_threshold_secs));

        s2n_custom_send_fn_called = false;
        conn->last_write_elapsed = 0;
        EXPECT_SUCCESS(s2n_send(conn, large_data.data, large_data.size, &blocked)); 
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_NOT_EQUAL(conn->last_write_elapsed, 0);
        EXPECT_EQUAL(conn->active_application_bytes_consumed, large_data.size);
    }

    /* s2n_send properly tracks bytes sent when a partial send occurs */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Send 1/3 of the large_data buffer then have control come back to the application. 1/3 is chosen to
         * help partition the data across multiple records. */
        ssize_t total_bytes_to_send = large_data.size / 3;
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&total_bytes_to_send));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_byte_limit_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;

        /* Use the 32KB large data buffer so multiple records are sent. */
        ssize_t written = s2n_send(conn, large_data.data, large_data.size, &blocked);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

        /* conn->current_user_data_consumed after a partial send will track how many bytes
         * were not sent over the wire successfully.
         *
         * written will be the amount of bytes successfully sent over the wire.
         *
         * conn->active_application_bytes_consumed tracks the total amount of bytes
         * read from the user buffer. (This is not true if using dynamic record sizes).
         * This means that conn->active_application_bytes_consumed should be equal to the
         * amount of bytes written successfully and the bytes that are still in the out stuffer. */
        ssize_t bytes_that_failed_to_send = conn->current_user_data_consumed;
        ssize_t bytes_that_successfully_sent = written;
        uint64_t total_bytes_processed_to_records = conn->active_application_bytes_consumed;
        EXPECT_EQUAL(bytes_that_failed_to_send + bytes_that_successfully_sent, total_bytes_processed_to_records);

        /* Move the callback to a mock send that will always send the entire stuffer. */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));

        s2n_custom_send_fn_called = false;
        /* We expect now that the total amount of bytes written will be equal to the large_data blob. */
        written += s2n_send(conn, large_data.data + written, large_data.size - written, &blocked);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(written, large_data.size);

        /* After an entire buffer has been sent, s2n_send should move conn->current_user_data_consumed back to 0. */ 
        EXPECT_EQUAL(conn->current_user_data_consumed, 0);
    }

    /* Very large s2n_send */
    {
        DEFER_CLEANUP(struct s2n_blob very_large_data = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&very_large_data, VERY_LARGE_SEND_SIZE));
        EXPECT_OK(s2n_get_public_random_data(&very_large_data));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));

        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN,
                                                       S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));

        ssize_t written = 0;
        s2n_blocked_status blocked = 0;

        while (written < very_large_data.size) {
            (void)s2n_recv(server_conn, very_large_data.data + written, very_large_data.size - written, &blocked);
            written += s2n_send(client_conn, very_large_data.data + written, very_large_data.size - written, &blocked);
        }
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(written, very_large_data.size);

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* Many small s2n_sends */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));

        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN,
                                                       S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));

        ssize_t written = 0;
        s2n_blocked_status blocked = 0;

        while (written < large_data.size) {
            ssize_t next_write_size = MIN(large_data.size - written, SMALL_CHUNK_SEND_SIZE);
            (void)s2n_recv(server_conn, large_data.data + written, next_write_size, &blocked);
            written += s2n_send(client_conn, large_data.data + written, next_write_size, &blocked);
        }
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(written, large_data.size);

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    END_TEST();
}
