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

#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

/*
 * The TLS protocol allows messages to be fragmented, interleaved and coalesced into 'records'. These
 * tests check that fragmented messages are recombined, that several messages in the same record work
 * and that messages interleaved with alerts (including a fragmented alert message) all work.
 *
 * To do this we fork() subprocesses that write records to a pipe, s2n is configured to read fragments
 * from the pipe.
 */

#define TLS_ALERT     21
#define TLS_HANDSHAKE 22
#define TLS_HEARTBEAT 24

#define ZERO_TO_THIRTY_ONE 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

uint8_t zero_to_thirty_one[] = { ZERO_TO_THIRTY_ONE };

uint8_t server_hello_message[] = { /* SERVER HELLO */
    0x02,

    /* Length */
    0x00, 0x00, 0x46,

    /* Protocol version */
    0x03, 0x03,

    /* Server random */
    ZERO_TO_THIRTY_ONE,

    /* SessionID len - 32 bytes */
    0x20,

    /* Session ID */
    ZERO_TO_THIRTY_ONE,

    /* Cipher suite - TLS_RSA_WITH_AES_256_CBC_SHA256 */
    0x00, 0x3D,

    /* Compression method: none  */
    0x00
};

uint8_t server_cert[] = { /* SERVER CERT */
    0x0B,

    /* Length of the handshake message */
    0x00, 0x03, 0x38,

    /* Length of all certificates */
    0x00, 0x03, 0x35,

    /* Length of the first cert */
    0x00, 0x03, 0x32,

    /* Certificate data - via openssl x509 -in cert.pem -outform DER | xxd -i */
    0x30, 0x82, 0x03, 0x2e, 0x30, 0x82, 0x02, 0x16, 0x02, 0x09, 0x00, 0xcb,
    0xd6, 0x5a, 0xfa, 0x37, 0xcf, 0xe0, 0xbf, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x59,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41,
    0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a,
    0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x18, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74,
    0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x12, 0x30,
    0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x6c, 0x6f, 0x63, 0x61,
    0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x34, 0x30,
    0x35, 0x31, 0x30, 0x31, 0x37, 0x30, 0x38, 0x32, 0x33, 0x5a, 0x17, 0x0d,
    0x32, 0x34, 0x30, 0x35, 0x30, 0x37, 0x31, 0x37, 0x30, 0x38, 0x32, 0x33,
    0x5a, 0x30, 0x59, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x08, 0x13, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74,
    0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x18,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64,
    0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
    0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x6c,
    0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
    0x02, 0x82, 0x01, 0x01, 0x00, 0xc8, 0x96, 0xd6, 0x94, 0x98, 0x78, 0x3e,
    0x1b, 0xb2, 0x1d, 0x6b, 0x65, 0xc2, 0xb4, 0x44, 0x31, 0xd5, 0x87, 0x96,
    0x0d, 0x7e, 0x35, 0x53, 0x6c, 0xc1, 0x29, 0xb6, 0x34, 0x95, 0x3f, 0x9a,
    0xb9, 0x77, 0xfc, 0xd5, 0xc4, 0xf7, 0x75, 0x84, 0xdd, 0x7c, 0x96, 0xe5,
    0x6f, 0xeb, 0xf8, 0x09, 0x35, 0x9a, 0x18, 0xda, 0x1f, 0xa2, 0x07, 0x33,
    0x79, 0xb9, 0xbc, 0x07, 0x6f, 0xce, 0x17, 0xd1, 0x7e, 0x59, 0x69, 0x0a,
    0x00, 0x98, 0x4a, 0xb1, 0x33, 0xc0, 0x13, 0xbf, 0xd2, 0x34, 0x07, 0x62,
    0xe0, 0x4a, 0xaf, 0xe0, 0x57, 0xcd, 0x6d, 0x62, 0xa4, 0x19, 0xbe, 0x31,
    0x69, 0xcc, 0x71, 0x6f, 0x83, 0xc7, 0xd9, 0x73, 0xfd, 0x57, 0x70, 0xa1,
    0x27, 0xa9, 0x4c, 0x48, 0x8d, 0xd5, 0xeb, 0xc1, 0x66, 0x11, 0xfe, 0x24,
    0x70, 0x43, 0x75, 0xe1, 0x5f, 0x2f, 0xb9, 0xf2, 0x02, 0xe4, 0x71, 0x3f,
    0x2d, 0x3e, 0x20, 0x08, 0xf0, 0xc9, 0xe1, 0x47, 0xd4, 0x51, 0xb0, 0x20,
    0x12, 0x14, 0x9e, 0x6d, 0x3e, 0xab, 0xfc, 0xa1, 0x58, 0x07, 0x94, 0xf7,
    0x01, 0xe0, 0xdc, 0xd5, 0x57, 0x67, 0x69, 0xa4, 0x5b, 0x96, 0xb3, 0xfa,
    0x2b, 0x03, 0x38, 0xe6, 0xf4, 0xec, 0xd0, 0x88, 0xb4, 0xf7, 0xf6, 0x2b,
    0x97, 0x30, 0x71, 0x69, 0x33, 0xcc, 0x8c, 0xb1, 0x82, 0x29, 0xaf, 0x09,
    0x32, 0xff, 0x0f, 0x5b, 0x64, 0x74, 0x53, 0xd5, 0x82, 0xa8, 0x79, 0xb3,
    0x04, 0x7f, 0x96, 0xdd, 0x0f, 0x71, 0x3e, 0xb7, 0xe1, 0x08, 0x89, 0xe6,
    0xe0, 0x95, 0xa8, 0x6f, 0xc5, 0xa0, 0x33, 0x53, 0x6e, 0x89, 0x8b, 0xb3,
    0x14, 0x1d, 0x02, 0x35, 0xa4, 0x1c, 0x74, 0xc4, 0xbb, 0x87, 0x46, 0x99,
    0x10, 0x05, 0x67, 0x6b, 0x28, 0x50, 0xf7, 0xaf, 0xcf, 0x69, 0xda, 0x63,
    0x28, 0xd1, 0x34, 0x2e, 0xea, 0xfd, 0x9d, 0x4c, 0x5b, 0x02, 0x03, 0x01,
    0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x64, 0x55,
    0xef, 0x5b, 0x91, 0xb7, 0xfd, 0x5d, 0x00, 0x3b, 0x0c, 0x0f, 0xd7, 0xe0,
    0x26, 0xfc, 0xd6, 0xf3, 0xd8, 0xc5, 0x00, 0xdf, 0x3b, 0x85, 0x70, 0x91,
    0x85, 0x35, 0xb1, 0x7d, 0x78, 0x58, 0x33, 0x39, 0x27, 0xc4, 0x9e, 0x56,
    0x31, 0xbd, 0x89, 0x02, 0x56, 0x8c, 0x73, 0xf8, 0x13, 0xa6, 0x20, 0xe2,
    0x40, 0x19, 0x1b, 0xbc, 0x1f, 0xa2, 0x25, 0xee, 0x40, 0x7a, 0x98, 0x10,
    0x59, 0xbc, 0xb1, 0x3c, 0x93, 0x6d, 0x4a, 0x50, 0x3d, 0x19, 0xf2, 0x81,
    0xcf, 0x52, 0x0d, 0x47, 0x97, 0x05, 0xb0, 0xe2, 0xf6, 0xed, 0x5a, 0xc1,
    0xa0, 0xc6, 0x07, 0x31, 0xaa, 0x25, 0xbd, 0xe7, 0xac, 0x95, 0xcd, 0x40,
    0x5b, 0x61, 0xdf, 0x06, 0xd5, 0xd6, 0x5d, 0xe5, 0x92, 0x10, 0x5e, 0xc5,
    0x40, 0xd8, 0x32, 0x7b, 0xc6, 0x43, 0x3c, 0xdc, 0xde, 0x49, 0x64, 0x88,
    0xd1, 0x5c, 0x8a, 0xdb, 0xbe, 0xb6, 0xc2, 0xc4, 0xe0, 0x4e, 0xe5, 0x21,
    0x1c, 0x06, 0x89, 0xe3, 0x9e, 0xba, 0xd1, 0xe5, 0xf9, 0xef, 0xe7, 0xbc,
    0x22, 0xf6, 0x8c, 0xef, 0x13, 0x84, 0x7c, 0x13, 0xc3, 0x29, 0x8b, 0x54,
    0xd1, 0xad, 0xbc, 0x66, 0xe8, 0x6f, 0x4a, 0xbd, 0x9a, 0x90, 0x9b, 0x46,
    0x0b, 0x07, 0x2c, 0xd8, 0x9e, 0xab, 0xb3, 0xa2, 0x3e, 0xad, 0x5f, 0x38,
    0x52, 0x4b, 0x43, 0xc4, 0x50, 0xbd, 0x2d, 0x47, 0xb3, 0x06, 0x8f, 0x03,
    0xf4, 0x59, 0x0c, 0x3c, 0xba, 0x0f, 0x28, 0xa3, 0x47, 0xd5, 0xd5, 0xd1,
    0xe8, 0xb3, 0xbc, 0x18, 0xe9, 0x2a, 0x59, 0x4a, 0xe1, 0x3c, 0x81, 0x26,
    0x7f, 0x2f, 0x4a, 0x61, 0xeb, 0x37, 0xab, 0x66, 0x57, 0xea, 0xcb, 0xe4,
    0xe2, 0xbc, 0x01, 0xb6, 0x89, 0xa6, 0x1d, 0x1b, 0xf7, 0xd2, 0x43, 0xf1,
    0x9e, 0x75, 0x35, 0x61, 0x7b, 0x79, 0xd9, 0x18, 0xbe, 0x5d, 0xcc, 0xce,
    0xc0, 0x4b
};

uint8_t heartbeat_message[] = {
    0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

uint8_t warning_alert[] = { /* warning: user cancelled */
    0x01, 0x5a
};

uint8_t fatal_alert[] = { /* Fatal: unexpected message */
    0x02, 0x0a
};

message_type_t s2n_conn_get_current_message_type(struct s2n_connection *conn);

void fragmented_message(int write_fd)
{
    int written = 0;
    /* Split the hello message into 5 fragments and write it */
    for (int i = 0; i < 5; i++) {
        int length = sizeof(server_hello_message) / 5;

        if (i == 0) {
            length += sizeof(server_hello_message) % 5;
        }

        uint8_t record_header[5] = { TLS_HANDSHAKE, 0x03, 0x03, (length >> 8), length & 0xff };

        if (write(write_fd, record_header, 5) != 5) {
            _exit(100);
        }

        if (write(write_fd, server_hello_message + written, length) != length) {
            _exit(100);
        }

        written += length;
    }

    /* Close the pipe and exit */
    close(write_fd);
}

void coalesced_message(int write_fd)
{
    int length = sizeof(server_hello_message) + sizeof(server_cert);

    uint8_t record_header[5] = { TLS_HANDSHAKE, 0x03, 0x03, (length >> 8), length & 0xff };

    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }

    if (write(write_fd, server_hello_message, sizeof(server_hello_message)) != sizeof(server_hello_message)) {
        _exit(100);
    }

    if (write(write_fd, server_cert, sizeof(server_cert)) != sizeof(server_cert)) {
        _exit(100);
    }

    close(write_fd);
}

void interleaved_message(int write_fd)
{
    int length = sizeof(server_hello_message) / 2;
    uint8_t record_header[5] = { TLS_HANDSHAKE, 0x03, 0x03, (length >> 8), length & 0xff };
    int written = 0;

    /* Write half of the message */
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message, length) != length) {
        _exit(100);
    }
    written += length;

    /* Write the heartbeat record */
    record_header[0] = TLS_HEARTBEAT;
    record_header[3] = sizeof(heartbeat_message) >> 8;
    record_header[4] = sizeof(heartbeat_message) & 0xff;

    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, heartbeat_message, sizeof(heartbeat_message)) != sizeof(heartbeat_message)) {
        _exit(100);
    }

    /* Write the rest of the hello message */
    length = sizeof(server_hello_message) - written;
    record_header[0] = TLS_HANDSHAKE;
    record_header[3] = length >> 8;
    record_header[4] = length & 0xff;
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message + written, length) != length) {
        _exit(100);
    }

    /* Close the pipe and exit */
    close(write_fd);
}

void interleaved_fragmented_fatal_alert(int write_fd)
{
    int length = sizeof(server_hello_message) / 2;
    uint8_t record_header[5] = { TLS_HANDSHAKE, 0x03, 0x03, (length >> 8), length & 0xff };
    int written = 0;

    /* Write half of the message */
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message, length) != length) {
        _exit(100);
    }
    written += length;

    /* Write half of the alert message */
    record_header[0] = TLS_ALERT;
    record_header[3] = 0;
    record_header[4] = 1;

    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, fatal_alert, 1) != 1) {
        _exit(100);
    }

    /* Write another quarter of the of the hello message */
    length = sizeof(server_hello_message) / 4;
    record_header[0] = TLS_HANDSHAKE;
    record_header[3] = length >> 8;
    record_header[4] = length & 0xff;
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message + written, length) != length) {
        _exit(100);
    }
    written += length;

    /* Write second half of the alert message */
    record_header[0] = TLS_ALERT;
    record_header[3] = 0;
    record_header[4] = 1;

    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, fatal_alert + 1, 1) != 1) {
        _exit(100);
    }

    /* Write the rest of the hello message */
    length = sizeof(server_hello_message) - written;
    record_header[0] = TLS_HANDSHAKE;
    record_header[3] = length >> 8;
    record_header[4] = length & 0xff;
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message + written, length) != length) {
        _exit(100);
    }

    /* Close the pipe and exit */
    close(write_fd);
}

void interleaved_fragmented_warning_alert(int write_fd)
{
    int length = sizeof(server_hello_message) / 2;
    uint8_t record_header[5] = { TLS_HANDSHAKE, 0x03, 0x03, (length >> 8), length & 0xff };
    int written = 0;

    /* Write half of the message */
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message, length) != length) {
        _exit(100);
    }
    written += length;

    /* Write half of the alert message */
    record_header[0] = TLS_ALERT;
    record_header[3] = 0;
    record_header[4] = 1;
    if (write(write_fd, warning_alert, 1) != 1) {
        _exit(100);
    }

    /* Write another quarter of the of the hello message */
    length = sizeof(server_hello_message) / 4;
    record_header[0] = TLS_HANDSHAKE;
    record_header[3] = length >> 8;
    record_header[4] = length & 0xff;
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message + written, length) != length) {
        _exit(100);
    }
    written += length;

    /* Write second half of the alert message */
    record_header[0] = TLS_ALERT;
    record_header[3] = 0;
    record_header[4] = 1;

    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, warning_alert + 1, 1) != 1) {
        _exit(100);
    }

    /* Write the rest of the hello message */
    length = sizeof(server_hello_message) - written;
    record_header[0] = TLS_HANDSHAKE;
    record_header[3] = length >> 8;
    record_header[4] = length & 0xff;
    if (write(write_fd, record_header, 5) != 5) {
        _exit(100);
    }
    if (write(write_fd, server_hello_message + written, length) != length) {
        _exit(100);
    }

    /* Close the pipe and exit */
    close(write_fd);
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    struct s2n_config *config;

    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int p[2];

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
    EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(config, 0));
    /* The server hello has TLS_RSA_WITH_AES_256_CBC_SHA256 hardcoded,
       so we need to set a cipher preference that will accept that value */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170328"));
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(p));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, p[0]));

    /* Pretend the client hello has already been set */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = SERVER_HELLO;

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(p[0]));

        /* Write the fragmented hello message */
        fragmented_message(p[1]);
        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        exit(0);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(p[1]));

    /* Negotiate the handshake. This will fail due to EOF, but that's ok. */
    EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

    /* Verify that the data is as we expect it */
    EXPECT_EQUAL(memcmp(conn->handshake_params.server_random, zero_to_thirty_one, 32), 0);

    /* Check that the server hello message was processed */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_CERT);

    /* Clean up */
    EXPECT_EQUAL(waitpid(pid, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(close(p[0]));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(p));

    /* Wipe the connection */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, p[0]));

    /* Pretend the client hello has already been set */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = SERVER_HELLO;

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(p[0]));

        /* Write the fragmented hello message */
        coalesced_message(p[1]);
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
        exit(0);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(p[1]));

    /* Negotiate the handshake. This will fail due to EOF, but that's ok. */
    EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

    /* Verify that the data is as we expect it */
    EXPECT_EQUAL(memcmp(conn->handshake_params.server_random, zero_to_thirty_one, 32), 0);

    /* Check that the server done message was processed */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO_DONE);

    /* Clean up */
    EXPECT_EQUAL(waitpid(pid, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(close(p[0]));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(p));

    /* Wipe the connection */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, p[0]));

    /* Pretend the client hello has already been set */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = SERVER_HELLO;

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(p[0]));

        /* Write the fragmented hello message */
        interleaved_message(p[1]);
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
        exit(0);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(p[1]));

    /* Negotiate the handshake. This will fail due to EOF, but that's ok. */
    EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

    /* Verify that the data is as we expect it */
    EXPECT_EQUAL(memcmp(conn->handshake_params.server_random, zero_to_thirty_one, 32), 0);

    /* Check that the server hello message was processed */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_CERT);

    /* Clean up */
    EXPECT_EQUAL(waitpid(pid, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(close(p[0]));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(p));

    /* Wipe the connection */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, p[0]));

    /* Pretend the client hello has already been set */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = SERVER_HELLO;

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(p[0]));

        /* Write the fragmented hello message */
        interleaved_fragmented_warning_alert(p[1]);
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
        exit(0);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(p[1]));

    /* Negotiate the handshake. This will fail due to EOF, but that's ok. */
    EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

    /* Verify that the data is as we expect it */
    EXPECT_NOT_EQUAL(memcmp(conn->handshake_params.server_random, zero_to_thirty_one, 32), 0);

    /* Check that the server hello message was not processed */
    EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO);

    /* Clean up */
    EXPECT_EQUAL(waitpid(pid, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(close(p[0]));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(p));

    /* Wipe the connection */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, p[0]));

    /* Pretend the client hello has already been set */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = SERVER_HELLO;

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(p[0]));

        /* Write the fragmented hello message */
        interleaved_fragmented_fatal_alert(p[1]);
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
        exit(0);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(p[1]));

    /* Negotiate the handshake. This will fail due to EOF, but that's ok. */
    EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

    /* Verify that the data failed */
    EXPECT_NOT_EQUAL(memcmp(conn->handshake_params.server_random, zero_to_thirty_one, 32), 0);

    /* Check that the server hello message was not processed */
    EXPECT_NOT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_CERT);

    /* Clean up */
    EXPECT_EQUAL(waitpid(pid, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(close(p[0]));

    EXPECT_SUCCESS(s2n_connection_free(conn));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
