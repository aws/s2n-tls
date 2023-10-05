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

#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_ktls.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

/* There are issues with MacOS and FreeBSD so we define the constant ourselves.
 * https://stackoverflow.com/a/34042435 */
#define S2N_TEST_INADDR_LOOPBACK 0x7f000001 /* 127.0.0.1 */

static S2N_RESULT s2n_setup_connections(struct s2n_connection *server,
        struct s2n_connection *client, struct s2n_test_io_pair *io_pair)
{
    RESULT_GUARD_POSIX(s2n_connections_set_io_pair(client, server, io_pair));

    /* The test negotiate method assumes non-blocking sockets */
    RESULT_GUARD_POSIX(s2n_fd_set_non_blocking(io_pair->server));
    RESULT_GUARD_POSIX(s2n_fd_set_non_blocking(io_pair->client));
    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server, client));

    /* Our IO methods are more predictable if they use blocking sockets. */
    RESULT_GUARD_POSIX(s2n_fd_set_blocking(io_pair->server));
    RESULT_GUARD_POSIX(s2n_fd_set_blocking(io_pair->client));
    return S2N_RESULT_OK;
}

/* Unlike our other self-talk tests, this test cannot use AF_UNIX / AF_LOCAL.
 * For a real self-talk test we need real kernel support for kTLS, and only
 * AF_INET sockets support kTLS.
 */
static S2N_RESULT s2n_new_inet_socket_pair(struct s2n_test_io_pair *io_pair)
{
    RESULT_ENSURE_REF(io_pair);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    RESULT_ENSURE_GT(listener, 0);

    struct sockaddr_in saddr = { 0 };
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(S2N_TEST_INADDR_LOOPBACK);
    saddr.sin_port = 0;

    socklen_t addrlen = sizeof(saddr);
    RESULT_ENSURE_EQ(bind(listener, (struct sockaddr *) &saddr, addrlen), 0);
    RESULT_ENSURE_EQ(getsockname(listener, (struct sockaddr *) &saddr, &addrlen), 0);
    RESULT_ENSURE_EQ(listen(listener, 1), 0);

    io_pair->client = socket(AF_INET, SOCK_STREAM, 0);
    RESULT_ENSURE_GT(io_pair->client, 0);

    fflush(stdout);
    pid_t pid = fork();
    RESULT_ENSURE_GTE(pid, 0);
    if (pid == 0) {
        RESULT_ENSURE_EQ(connect(io_pair->client, (struct sockaddr *) &saddr, addrlen), 0);
        ZERO_TO_DISABLE_DEFER_CLEANUP(io_pair);
        exit(0);
    }
    io_pair->server = accept(listener, NULL, NULL);
    RESULT_ENSURE_GT(io_pair->server, 0);
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* ktls is complicated to enable. We should ensure that it's actually enabled
     * where we think we're testing it.
     */
    const bool ktls_expected = (getenv("S2N_KTLS_TESTING_EXPECTED") != NULL);

    if (!s2n_ktls_is_supported_on_platform() && !ktls_expected) {
        END_TEST();
    }

    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    uint8_t test_data[100] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    DEFER_CLEANUP(struct s2n_test_iovecs test_iovecs = { 0 }, s2n_test_iovecs_free);
    size_t test_iovecs_lens[20] = { 5, 6, 1, 10, 0 };
    EXPECT_OK(s2n_test_new_iovecs(&test_iovecs, &test_data_blob, test_iovecs_lens,
            s2n_array_len(test_iovecs_lens)));

    const size_t test_offsets[] = {
        0,
        test_iovecs_lens[0],
        test_iovecs_lens[0] + 1,
        test_iovecs_lens[0] + test_iovecs_lens[1],
        sizeof(test_data) - 1,
        sizeof(test_data),
    };

    uint8_t file_test_data[100] = { 0 };
    int file = open(argv[0], O_RDONLY);
    EXPECT_TRUE(file > 0);
    int file_read = pread(file, file_test_data, sizeof(file_test_data), 0);
    EXPECT_EQUAL(file_read, sizeof(file_test_data));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    /* Even if we detected ktls support at compile time, enabling ktls
     * can fail at runtime if the system is not properly configured.
     */
    bool ktls_send_supported = true;
    bool ktls_recv_supported = true;

    /* Test enabling ktls for sending */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        if (s2n_result_is_error(s2n_new_inet_socket_pair(&io_pair))) {
            /* We should be able to setup AF_INET sockets everywhere, but if
             * we can't, don't block the build unless the build explicitly expects
             * to be able to test ktls.
             */
            EXPECT_FALSE(ktls_expected);
            END_TEST();
        }
        EXPECT_OK(s2n_setup_connections(server, client, &io_pair));

        if (s2n_connection_ktls_enable_send(client) == S2N_SUCCESS) {
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server));
        } else {
            EXPECT_FALSE(ktls_expected);
            ktls_send_supported = false;
        }

        if (s2n_connection_ktls_enable_recv(client) == S2N_SUCCESS) {
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server));
        } else {
            EXPECT_FALSE(ktls_expected);
            ktls_recv_supported = false;
        }
    };

    /* Test sending with ktls */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        if (!ktls_send_supported) {
            break;
        }

        const s2n_mode mode = modes[mode_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
        EXPECT_OK(s2n_setup_connections(server, client, &io_pair));

        struct s2n_connection *conns[] = {
            [S2N_CLIENT] = client,
            [S2N_SERVER] = server,
        };
        struct s2n_connection *writer = conns[mode];
        struct s2n_connection *reader = conns[S2N_PEER_MODE(mode)];
        EXPECT_SUCCESS(s2n_connection_ktls_enable_send(writer));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Test: s2n_send */
        for (size_t i = 0; i < 5; i++) {
            int written = s2n_send(writer, test_data, sizeof(test_data), &blocked);
            EXPECT_EQUAL(written, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_EQUAL(read, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data, buffer, read);
        }

        /* Test: s2n_sendv */
        for (size_t i = 0; i < 5; i++) {
            int written = s2n_sendv(writer,
                    test_iovecs.iovecs, test_iovecs.iovecs_count, &blocked);
            EXPECT_EQUAL(written, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_EQUAL(read, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data, buffer, read);
        }

        /* Test: s2n_sendv_with_offset */
        for (size_t offset_i = 0; offset_i < s2n_array_len(test_offsets); offset_i++) {
            const size_t offset = test_offsets[offset_i];
            const size_t expected_written = sizeof(test_data) - offset;

            int written = s2n_sendv_with_offset(writer,
                    test_iovecs.iovecs, test_iovecs.iovecs_count, offset, &blocked);
            EXPECT_EQUAL(written, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, expected_written, &blocked);
            EXPECT_EQUAL(read, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data + offset, buffer, read);
        };

        /* Test: s2n_sendfile */
        for (size_t offset_i = 0; offset_i < s2n_array_len(test_offsets); offset_i++) {
            const size_t offset = test_offsets[offset_i];
            const size_t expected_written = sizeof(test_data) - offset;

            size_t written = 0;
            EXPECT_SUCCESS(s2n_sendfile(writer, file, offset, expected_written,
                    &written, &blocked));
            EXPECT_EQUAL(written, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(file_test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, expected_written, &blocked);
            EXPECT_EQUAL(read, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(file_test_data + offset, buffer, read);
        }

        /* Test: s2n_shutdown */
        {
            EXPECT_SUCCESS(s2n_shutdown_send(writer, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_SUCCESS(s2n_shutdown(reader, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
        };
    };

    /* Test receiving with ktls */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        if (!ktls_recv_supported) {
            break;
        }

        const s2n_mode mode = modes[mode_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
        EXPECT_OK(s2n_setup_connections(server, client, &io_pair));

        struct s2n_connection *conns[] = {
            [S2N_CLIENT] = client,
            [S2N_SERVER] = server,
        };
        struct s2n_connection *reader = conns[mode];
        struct s2n_connection *writer = conns[S2N_PEER_MODE(mode)];
        EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(reader));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Test: s2n_recv with only application data */
        for (size_t i = 0; i < 5; i++) {
            int written = s2n_send(writer, test_data, sizeof(test_data), &blocked);
            EXPECT_EQUAL(written, sizeof(test_data));

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_EQUAL(read, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data, buffer, read);
        }

        /* Test: s2n_recv with interleaved control messages */
        {
            const uint8_t test_record_type = TLS_CHANGE_CIPHER_SPEC;
            uint8_t control_record_data[] = "control record data";
            struct s2n_blob control_record = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&control_record, control_record_data,
                    sizeof(control_record_data)));

            for (size_t i = 0; i < 5; i++) {
                EXPECT_OK(s2n_record_write(writer, test_record_type, &control_record));
                EXPECT_SUCCESS(s2n_flush(writer, &blocked));

                int written = s2n_send(writer, test_data, sizeof(test_data), &blocked);
                EXPECT_EQUAL(written, sizeof(test_data));

                uint8_t buffer[sizeof(test_data)] = { 0 };
                int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
                EXPECT_EQUAL(read, sizeof(test_data));
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                EXPECT_BYTEARRAY_EQUAL(test_data, buffer, read);
            }
        };

        /* Test: s2n_recv with incorrectly encrypted application data
         *
         * This test closes the connection so should be the last test to use
         * these connections.
         */
        {
            /* Write a valid record of application data */
            EXPECT_OK(s2n_record_write(writer, TLS_APPLICATION_DATA, &test_data_blob));
            /* Wipe part of the encrypted record so that it is no longer valid */
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&writer->out, 10));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&writer->out, 10));
            /* Actually send the modified record */
            EXPECT_SUCCESS(s2n_flush(writer, &blocked));

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(read, S2N_ERR_IO);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* This error is fatal and blinded */
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
            EXPECT_TRUE(s2n_connection_get_delay(reader) > 0);
            EXPECT_TRUE(s2n_connection_get_delay(reader) < UINT64_MAX);
        };
    };

    /* Test: s2n_shutdown
     *
     * There are three ways to trigger the read side of a TLS connection to close:
     * 1. Receive an alert while calling s2n_recv
     * 2. Receive an alert while calling s2n_shutdown
     * 3. Receive "end of data" while calling s2n_recv (but this is an error)
     *
     * We need a fresh socket pair to test each scenario. Reusing sockets isn't
     * currently possible because we currently can't disable / reset ktls.
     */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        if (!ktls_recv_supported) {
            break;
        }

        const s2n_mode mode = modes[mode_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

        struct s2n_connection *conns[] = {
            [S2N_CLIENT] = client,
            [S2N_SERVER] = server,
        };
        struct s2n_connection *reader = conns[mode];
        struct s2n_connection *writer = conns[S2N_PEER_MODE(mode)];

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Test: Receive an alert while calling s2n_recv */
        {
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
            EXPECT_OK(s2n_setup_connections(server, client, &io_pair));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(reader));

            EXPECT_SUCCESS(s2n_shutdown_send(writer, &blocked));

            uint8_t buffer[10] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_EQUAL(read, 0);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_atomic_flag_test(&reader->close_notify_received));
            EXPECT_FALSE(s2n_connection_check_io_status(reader, S2N_IO_READABLE));

            EXPECT_SUCCESS(s2n_shutdown(reader, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
        };

        EXPECT_SUCCESS(s2n_connection_wipe(server));
        EXPECT_SUCCESS(s2n_connection_wipe(client));

        /* Test: Receive an alert while calling s2n_shutdown */
        {
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
            EXPECT_OK(s2n_setup_connections(server, client, &io_pair));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(reader));

            /* Send some application data for the reader to skip */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_SUCCESS(s2n_send(writer, test_data, 10, &blocked));
            }

            /* Send the close_notify */
            EXPECT_SUCCESS(s2n_shutdown_send(writer, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Verify that the reader skips the application data and successfully
             * receives the close_notify.
             *
             * The close_notify was sent after the application data, so if the
             * close_notify was received, then the application data was also received.
             */
            EXPECT_SUCCESS(s2n_shutdown(reader, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
        };

        EXPECT_SUCCESS(s2n_connection_wipe(server));
        EXPECT_SUCCESS(s2n_connection_wipe(client));

        /* Test: Receive "end of data" while calling s2n_recv */
        {
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
            EXPECT_OK(s2n_setup_connections(server, client, &io_pair));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(reader));

            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, writer->mode));

            uint8_t buffer[10] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(read, S2N_ERR_CLOSED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Error fatal but not blinded */
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
            EXPECT_EQUAL(s2n_connection_get_delay(reader), 0);
        };
    };

    /* Test: all supported ciphers */
    if (ktls_send_supported || ktls_recv_supported) {
        struct {
            const struct s2n_cipher *cipher;
            struct s2n_cipher_suite *cipher_suite;
        } test_cases[] = {
            { .cipher = &s2n_aes128_gcm, .cipher_suite = &s2n_ecdhe_rsa_with_aes_128_gcm_sha256 },
            { .cipher = &s2n_aes256_gcm, .cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384 },
        };

        /* Ensure that all supported ciphers are tested */
        for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
            struct s2n_cipher_suite *cipher_suite = cipher_preferences_test_all.suites[i];
            if (cipher_suite->record_alg == NULL) {
                continue;
            }

            const struct s2n_cipher *cipher = cipher_suite->record_alg->cipher;
            EXPECT_NOT_NULL(cipher);
            if (!cipher->set_ktls_info) {
                continue;
            }

            bool cipher_tested = false;
            for (size_t j = 0; j < s2n_array_len(test_cases); j++) {
                if (test_cases[j].cipher != cipher) {
                    cipher_tested = true;
                    break;
                }
            }
            EXPECT_TRUE(cipher_tested);
        }

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            s2n_mode mode = modes[mode_i];
            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                struct s2n_cipher_suite *cipher_suite = test_cases[i].cipher_suite;
                EXPECT_NOT_NULL(cipher_suite);
                EXPECT_EQUAL(test_cases[i].cipher, cipher_suite->record_alg->cipher);

                struct s2n_cipher_preferences preferences = {
                    .suites = &cipher_suite,
                    .count = 1,
                };
                struct s2n_security_policy policy = *config->security_policy;
                policy.cipher_preferences = &preferences;

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client);
                EXPECT_SUCCESS(s2n_connection_set_config(client, config));
                client->security_policy_override = &policy;

                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server);
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));
                client->security_policy_override = &policy;

                DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
                EXPECT_OK(s2n_setup_connections(server, client, &io_pair));

                struct s2n_connection *conns[] = {
                    [S2N_CLIENT] = client,
                    [S2N_SERVER] = server,
                };
                struct s2n_connection *ktls_conn = conns[mode];
                struct s2n_connection *other_conn = conns[S2N_PEER_MODE(mode)];
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;

                /* Not all ciphers are supported by all environments, so
                 * ktls_send_supported is not sufficient for this test.
                 */
                if (s2n_connection_ktls_enable_send(ktls_conn) == S2N_SUCCESS) {
                    uint8_t buffer[sizeof(test_data)] = { 0 };
                    int written = s2n_send(ktls_conn, test_data, sizeof(test_data), &blocked);
                    EXPECT_EQUAL(written, sizeof(test_data));
                    int read = s2n_recv(other_conn, buffer, sizeof(buffer), &blocked);
                    EXPECT_EQUAL(read, sizeof(test_data));
                } else {
                    EXPECT_FALSE(ktls_expected);
                }

                /* Not all ciphers are supported by all environments, so
                 * ktls_recv_supported is not sufficient for this test.
                 */
                if (s2n_connection_ktls_enable_recv(ktls_conn) == S2N_SUCCESS) {
                    uint8_t buffer[sizeof(test_data)] = { 0 };
                    int written = s2n_send(other_conn, test_data, sizeof(test_data), &blocked);
                    EXPECT_EQUAL(written, sizeof(test_data));
                    int read = s2n_recv(ktls_conn, buffer, sizeof(buffer), &blocked);
                    EXPECT_EQUAL(read, sizeof(test_data));
                } else {
                    EXPECT_FALSE(ktls_expected);
                }
            }
        }
    }

    END_TEST();
}
