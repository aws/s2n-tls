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

#include "api/s2n.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

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

static int s2n_broken_pipe_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    (void) io_context;

    /* Break loop on second call. */
    if (s2n_custom_send_fn_called) {
        errno = EPIPE;
        return -1;
    }

    s2n_custom_send_fn_called = true;

    int partial_read = len-3;

    sent_bytes = partial_read;
    errno = EAGAIN;

    return partial_read;
}

static int s2n_fail_send_with_injected_errno_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    errno = *(int*)io_context;
    s2n_custom_send_fn_called = true;

    return S2N_FAILURE;
}

static int s2n_send_alert_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;

    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->alert_in));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, buf, len));

    /* We expect a fatal alert to be sent. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(conn), S2N_ERR_ALERT);
    EXPECT_TRUE(conn->closed);

    return len;
}

static int s2n_send_always_passes_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;

    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->out, buf, len));

    return len;
}

static int s2n_send_mitigates_beast_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;
    uint32_t *writes = (uint32_t*) s2n_connection_get_ctx(conn);

    /* The BEAST mitigation in s2n_send should first send a 1 byte record and then the rest of the application data. */
    uint32_t expected_write_sizes[] = {1, 12};

    EXPECT_EQUAL(conn->current_user_data_consumed, expected_write_sizes[*writes]);

    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->out, buf, len));

    *writes += 1;

    return len;
}

static int s2n_partial_socket_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    uint32_t *written_bytes = (uint32_t*) s2n_connection_get_ctx(conn);

    /* Break loop on second call. */
    if (s2n_custom_send_fn_called) {
        errno = EAGAIN;
        return -1;
    }

    s2n_custom_send_fn_called = true;
    int partial_read = len-3;

    *written_bytes = partial_read;
    errno = EAGAIN;

    return partial_read;
}

static int s2n_dynamic_record_sizing_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;
    uint32_t *writes = (uint32_t*) s2n_connection_get_ctx(conn);
    
    uint16_t min_payload_size = 0;
    POSIX_GUARD_RESULT(s2n_record_min_write_payload_size(conn, &min_payload_size));
    EXPECT_EQUAL(1398, min_payload_size);

    /* Until we hit the dynamic record resize threshold we expect that the records are divisible
     * by the s2n_record_min_write_payload_size. */
    if (conn->active_application_bytes_consumed <= conn->dynamic_record_resize_threshold) {
        /* The test is set up so dynamic record sizes are only used in the first and third writes. */
        EXPECT_TRUE(*writes == 1 || *writes == 3);
        EXPECT_EQUAL(conn->current_user_data_consumed % min_payload_size, 0);
    }

    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->out, buf, len));

    return len;
}

static int s2n_counted_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;
    ssize_t *bytes_to_send = (ssize_t*) s2n_connection_get_ctx(conn);

    /* Cede control back to application when the bytes_to_send threshold is reached. */
    if (conn->current_user_data_consumed > *bytes_to_send) {
        errno = EAGAIN;
        return -1;
    }

    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->out, buf, len));

    return len;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Buffer filled with an arbitrary string for testing. */
    uint8_t test_data[] = "hello world";

    DEFER_CLEANUP(struct s2n_blob large_data = {0}, s2n_free);
    /* Allocate 32KB so it takes multiple records to send complete data. */
    EXPECT_SUCCESS(s2n_alloc(&large_data, 1 << 15));
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

    /* s2n_flush modifies a closing socket to closed. */
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

    /* s2n_flush sets s2n_errno based on errno */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_fail_send_with_injected_errno_fn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->out, test_data, sizeof(test_data)));

        /* Assumes less than 512 possible errno values. This value is arbitrary and can be adjusted. */
        for(int i = 1; i < 512; i++) {
            int injected_errno = i;
            EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) &injected_errno));

            s2n_blocked_status blocked = 0;
            s2n_custom_send_fn_called = false;

            switch(injected_errno) {
                case EINTR:
                    /* EINTR is retried in an unbounded loop. */
                    s2n_custom_send_fn_called = true;
                    break;

                /* EAGAIN and EWOULDBLOCK can sometimes be the same value. 
                 * Switch statements can currently not be compiled with the
                 * same value so only one case is used. */
                case EWOULDBLOCK:
                    EXPECT_FAILURE_WITH_ERRNO(s2n_flush(conn, &blocked),
                            S2N_ERR_IO_BLOCKED);
                    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                    break;

                case EPIPE:
                    EXPECT_FAILURE_WITH_ERRNO(s2n_flush(conn, &blocked),
                            S2N_ERR_IO);
                    EXPECT_TRUE(conn->write_fd_broken);
                    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                    conn->write_fd_broken = 0;
                    break;

                default:
                    EXPECT_FAILURE_WITH_ERRNO(s2n_flush(conn, &blocked),
                            S2N_ERR_IO);
                    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                    break;
            }
            EXPECT_TRUE(s2n_custom_send_fn_called);
        }
    }

    /* s2n_flush will write any pending alerts and close the socket. */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_alert_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

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

    /* s2n_send enforces RE-ENTRENCY. */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        s2n_blocked_status blocked = 0;

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        EXPECT_FALSE(conn->send_in_use);
        EXPECT_SUCCESS(s2n_send(conn, test_data, sizeof(test_data), &blocked));
        EXPECT_FALSE(conn->send_in_use);

        conn->send_in_use = true;

        EXPECT_TRUE(conn->send_in_use);
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_REENTRANCY);
        EXPECT_TRUE(conn->send_in_use);
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

    /* s2n_sendv_with_offset errors when Quic is enabled */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_connection_enable_quic(conn));
            EXPECT_FAILURE_WITH_ERRNO(s2n_sendv_with_offset(conn, NULL, 0, 0, NULL), S2N_ERR_UNSUPPORTED_WITH_QUIC);
        }
    }

    /* s2n_sendv_with_offset mitigates BEAST with small writes  */
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

    /* s2n_send partial writes are flushed in proceeding sends */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        uint32_t actual_bytes_written = 0;
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&actual_bytes_written));

        s2n_blocked_status blocked = 0;

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_partial_socket_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        s2n_custom_send_fn_called = false;

        /* Assume we have a partial write of sizeof(test_data) - 1 that was successful.
         * The subsequent socket write failed with EAGAIN, and control has returned to the application.*/
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(conn->current_user_data_consumed, sizeof(test_data));
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

        /* This is to be kept in sync with the partial write performed by s2n_partial_socket_send_fn.
         * As of this comment it will perform the entire write except the last 3 bytes. */
        uint32_t expected_remaining_data = sizeof(test_data) - (sizeof(test_data) - 3);
        EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), expected_remaining_data);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));
        EXPECT_SUCCESS(s2n_send(conn, test_data, sizeof(test_data), &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(conn->current_user_data_consumed, 0);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
    }

    /* s2n_send supports dynamic record sizes */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Write 16KB of small dynamic record size. */
        uint32_t resize_threshold = 1 << 14;
        /* Choose a long time out so the first two calls to s2n_send do not reset the dynamic record size threshold. */
        uint16_t timeout_threshold_secs = UINT16_MAX;
        EXPECT_SUCCESS(s2n_connection_set_dynamic_record_threshold(conn, resize_threshold, timeout_threshold_secs));

        uint32_t writes = 1;

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_dynamic_record_sizing_fn));
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&writes));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;

        /* Make sure that the timer is set after the dynamic_record_timeout_threshold is hit. */
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

        /* Two full sends with no dynamic record size reset. */
        EXPECT_EQUAL(conn->active_application_bytes_consumed, large_data.size * 2);

        writes += 1;

        /* Here we reset the clock and move the timeout threshold, forcing a reset. */
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

    /* s2n_send guards against a partial_send that retries with a smaller buffer than the previous s2n_send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Send 1/3 of the large_data buffer then have control come back to the application. */
        ssize_t total_bytes_to_send = large_data.size / 3;
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&total_bytes_to_send));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_counted_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;

        s2n_custom_send_fn_called = false;
        /* Use large data so multiple records are written. */
        ssize_t written = s2n_send(conn, large_data.data, large_data.size, &blocked);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

        /* Subsequent writes should only be decreasing. */
        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, large_data.data, written - large_data.size, &blocked), S2N_ERR_SEND_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
    }

    /* s2n_send properly tracks bytes across partial sends */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Send 1/3 of the large_data buffer then have control come back to the application. */
        ssize_t total_bytes_to_send = large_data.size / 3;
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*)&total_bytes_to_send));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_counted_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;

        /* Use large data so multiple records are written. */
        ssize_t written = s2n_send(conn, large_data.data, large_data.size, &blocked);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(conn->current_user_data_consumed + written, conn->active_application_bytes_consumed);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));

        s2n_custom_send_fn_called = false;
        written += s2n_send(conn, large_data.data + written, large_data.size - written, &blocked);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(conn->current_user_data_consumed, 0);
        EXPECT_EQUAL(written, large_data.size);
    }

    END_TEST();
}
