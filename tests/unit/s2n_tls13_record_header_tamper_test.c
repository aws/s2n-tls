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

/*
 * Test that s2n-tls correctly rejects TLS 1.3 records whose outer
 * content_type has been modified in transit.
 *
 * RFC 8446 Section 5.2 requires that the outer content_type of all encrypted
 * TLS 1.3 records MUST be TLS_APPLICATION_DATA (0x17). The AEAD additional
 * authenticated data (AAD) hardcodes this value rather than using the actual
 * wire byte, so the outer content_type is not covered by the authentication
 * tag.
 *
 * Previously, if the outer content_type was changed to a value not handled by
 * the dispatch logic in s2n_recv_impl, the decrypted record would be discarded
 * without surfacing an error. This test verifies that such records are now
 * properly rejected with S2N_ERR_BAD_MESSAGE per RFC 8446 Section 5.2.
 */

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls_parameters.h"

/* An invalid content_type value that is not TLS_CHANGE_CIPHER_SPEC (20),
 * TLS_ALERT (21), TLS_HANDSHAKE (22), or TLS_APPLICATION_DATA (23).
 * This will fall through the switch in s2n_recv_impl with no handler. */
#define INVALID_CONTENT_TYPE 0x18

int main(int argc, char **argv)
{
    BEGIN_TEST();
    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

    /* Test: Modifying the outer content_type of a TLS 1.3 encrypted record
     * to an unrecognized value must be detected and rejected.
     *
     * This simulates an on-path modification of byte 0 of the 5-byte TLS
     * record header from 0x17 (TLS_APPLICATION_DATA) to 0x18, which is
     * not a valid content_type for encrypted records per RFC 8446 Section 5.2.
     */
    {
        const char request_1[] = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n";
        const char request_2[] = "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";
        const char request_3[] = "GET /third HTTP/1.1\r\nHost: example.com\r\n\r\n";

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        /* Use stuffers for IO so we can intercept and modify wire data */
        DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

        /* Complete TLS 1.3 handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        /* Client sends three "HTTP requests", each in its own TLS record */
        EXPECT_EQUAL(s2n_send(client_conn, request_1, sizeof(request_1), &blocked), sizeof(request_1));
        uint32_t record_1_size = s2n_stuffer_data_available(&server_in);
        EXPECT_TRUE(record_1_size > 0);

        EXPECT_EQUAL(s2n_send(client_conn, request_2, sizeof(request_2), &blocked), sizeof(request_2));
        uint32_t record_2_size = s2n_stuffer_data_available(&server_in) - record_1_size;
        EXPECT_TRUE(record_2_size > 0);

        EXPECT_EQUAL(s2n_send(client_conn, request_3, sizeof(request_3), &blocked), sizeof(request_3));

        /* === ATTACKER ACTION ===
         * Flip the outer content_type of the SECOND record from
         * TLS_APPLICATION_DATA (0x17) to an unrecognized value (0x18).
         *
         * The first byte of each TLS record is the content_type.
         * Record 1 starts at offset 0, record 2 starts at offset record_1_size.
         */
        uint8_t *wire_data = server_in.blob.data + server_in.read_cursor;
        uint8_t original_byte = wire_data[record_1_size];
        EXPECT_EQUAL(original_byte, TLS_APPLICATION_DATA);
        wire_data[record_1_size] = INVALID_CONTENT_TYPE;

        /* Server reads: should get request_1 from the first record */
        uint8_t recv_buf[1024] = { 0 };
        ssize_t bytes_read = s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked);
        EXPECT_EQUAL(bytes_read, sizeof(request_1));
        EXPECT_BYTEARRAY_EQUAL(recv_buf, request_1, sizeof(request_1));

        /* Server reads again: the second record has a modified content_type.
         *
         * s2n_record_parse rejects TLS 1.3 encrypted records whose outer
         * content_type is not TLS_APPLICATION_DATA, per RFC 8446 Section 5.2.
         * The modified record produces a fatal error.
         */
        memset(recv_buf, 0, sizeof(recv_buf));
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                S2N_ERR_BAD_MESSAGE);

        /* Verify the connection remains in an error state — subsequent reads
         * must not deliver later records. */
        memset(recv_buf, 0, sizeof(recv_buf));
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                S2N_ERR_CLOSED);
    };

    /* Test: Every content_type value in 0x00–0x7F other than
     * TLS_APPLICATION_DATA (0x17) is rejected with S2N_ERR_BAD_MESSAGE
     * on a post-handshake TLS 1.3 encrypted record.
     *
     * Skipped values:
     * - TLS_APPLICATION_DATA (0x17): the correct value, not modified.
     *
     * Values >= 0x80 are excluded because the high bit is interpreted as
     * the SSLv2 header flag (S2N_TLS_SSLV2_HEADER_FLAG), which triggers
     * a different record parsing path unrelated to this fix.
     */
    {
        for (uint16_t content_type = 0; content_type <= 0x7F; content_type++) {
            /* Skip APPLICATION_DATA — the correct value */
            if (content_type == TLS_APPLICATION_DATA) {
                continue;
            }

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

            const char payload[] = "SENSITIVE DATA THAT SHOULD NOT BE DROPPED";
            const char canary[] = "CANARY AFTER DROPPED RECORD";

            /* Send two records: payload (content_type will be modified) and canary. */
            EXPECT_EQUAL(s2n_send(client_conn, payload, sizeof(payload), &blocked), sizeof(payload));
            uint32_t first_record_size = s2n_stuffer_data_available(&server_in);
            EXPECT_TRUE(first_record_size > 0);

            EXPECT_EQUAL(s2n_send(client_conn, canary, sizeof(canary), &blocked), sizeof(canary));
            EXPECT_EQUAL(s2n_send(client_conn, canary, sizeof(canary), &blocked), sizeof(canary));

            /* Modify the first record's content_type */
            uint8_t *wire = server_in.blob.data + server_in.read_cursor;
            EXPECT_EQUAL(wire[0], TLS_APPLICATION_DATA);
            wire[0] = (uint8_t) content_type;

            /* The modified record is rejected with S2N_ERR_BAD_MESSAGE
             * per RFC 8446 Section 5.2. */
            uint8_t recv_buf[1024] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                    S2N_ERR_BAD_MESSAGE);

            /* Verify the connection is not usable on subsequent reads. */
            memset(recv_buf, 0, sizeof(recv_buf));
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                    S2N_ERR_CLOSED);
        }
    };

    /* Test: Content_type values 0x80–0xFF (high bit set) are rejected.
     *
     * Values with the high bit set are interpreted as SSLv2 record headers
     * (S2N_TLS_SSLV2_HEADER_FLAG), which triggers a different parsing path.
     * The SSLv2 path expects a differently-structured header and will fail
     * when it encounters AEAD-encrypted record data. We verify that the
     * connection is not usable after the modification.
     */
    {
        for (uint16_t content_type = 0x80; content_type <= 0xFF; content_type++) {
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

            const char payload[] = "data for SSLv2 header flag test";

            EXPECT_EQUAL(s2n_send(client_conn, payload, sizeof(payload), &blocked), sizeof(payload));

            /* Modify content_type to a value with the high bit set */
            uint8_t *wire = server_in.blob.data + server_in.read_cursor;
            EXPECT_EQUAL(wire[0], TLS_APPLICATION_DATA);
            wire[0] = (uint8_t) content_type;

            /* The SSLv2 parsing path will fail — the exact error varies
             * depending on how the remaining header bytes are interpreted.
             * We just verify the recv does not succeed. */
            uint8_t recv_buf[1024] = { 0 };
            EXPECT_FAILURE(s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked));

            /* Verify the connection is not usable on subsequent reads. */
            memset(recv_buf, 0, sizeof(recv_buf));
            EXPECT_FAILURE(s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked));
        }
    };

    /* Test: CCS content_type (0x14) on a post-handshake encrypted record
     * is rejected.
     *
     * RFC 8446 Appendix D.4 specifies that CCS is only valid during the
     * handshake. After the handshake completes, s2n_is_tls13_plaintext_content
     * no longer routes CCS through the null cipher path, so the record
     * reaches the encrypted record validation and is rejected.
     *
     * This is tested separately because CCS takes a different code path
     * than other invalid content_types: it passes header validation (0x14
     * is in the valid set) and was previously routed through the plaintext
     * content path regardless of handshake state.
     */
    {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        const char payload[] = "data protected by TLS 1.3";

        EXPECT_EQUAL(s2n_send(client_conn, payload, sizeof(payload), &blocked), sizeof(payload));

        /* Modify content_type from APPLICATION_DATA to CHANGE_CIPHER_SPEC */
        uint8_t *wire = server_in.blob.data + server_in.read_cursor;
        EXPECT_EQUAL(wire[0], TLS_APPLICATION_DATA);
        wire[0] = TLS_CHANGE_CIPHER_SPEC;

        uint8_t recv_buf[1024] = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                S2N_ERR_BAD_MESSAGE);

        /* Connection is closed after the error */
        memset(recv_buf, 0, sizeof(recv_buf));
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                S2N_ERR_CLOSED);
    };

    /* Test: ALERT content_type (0x15) on a post-handshake encrypted record
     * is rejected with S2N_ERR_BAD_MESSAGE.
     *
     * After the handshake completes, plaintext alerts are no longer routed
     * through the null cipher path. The record reaches the encrypted record
     * validation in s2n_record_parse, which rejects it because the outer
     * content_type is not TLS_APPLICATION_DATA.
     *
     * This prevents an on-path attacker from flipping the outer content_type
     * to ALERT (0x15) to route raw AEAD ciphertext into the alert parser,
     * where certain ciphertext byte patterns (close_notify at 1/256,
     * user_canceled at 1/256) could be silently consumed without
     * incrementing the AEAD sequence number.
     */
    {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        const char payload[] = "data protected by TLS 1.3";

        EXPECT_EQUAL(s2n_send(client_conn, payload, sizeof(payload), &blocked), sizeof(payload));

        /* Modify content_type from APPLICATION_DATA to ALERT */
        uint8_t *wire = server_in.blob.data + server_in.read_cursor;
        EXPECT_EQUAL(wire[0], TLS_APPLICATION_DATA);
        wire[0] = TLS_ALERT;

        /* The record is rejected by s2n_record_parse because the outer
         * content_type is not TLS_APPLICATION_DATA for a TLS 1.3 encrypted
         * record (non-null cipher). */
        uint8_t recv_buf[1024] = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                S2N_ERR_BAD_MESSAGE);

        /* Verify the connection is not usable after the error */
        memset(recv_buf, 0, sizeof(recv_buf));
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server_conn, recv_buf, sizeof(recv_buf), &blocked),
                S2N_ERR_CLOSED);
    };

    END_TEST();
}
