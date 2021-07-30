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

#include <benchmark/benchmark.h>
#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <cstring>

#include <vector>
#define STDIO_BUFSIZE  10240

#define DEBUG_PRINT 0
#define DEBUG_CIPHER 0
#define ITERATIONS 50

extern int rc;

extern "C" {
#define S2N_ECC_EVP_SUPPORTED_CURVES_COUNT 4

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>

#include <s2n.h>
#include "bin/common.h"
#include <error/s2n_errno.h>

#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"
#define S2N_MAX_ECC_CURVE_NAME_LENGTH 10
}

//36 total
const char* suite_names_benchmark[] = {
        "s2n_ecdhe_rsa_with_aes_128_cbc_sha256",
        "s2n_dhe_rsa_with_aes_256_gcm_sha384",
        "s2n_rsa_with_rc4_128_md5",
        "s2n_rsa_with_rc4_128_sha",
        "s2n_rsa_with_3des_ede_cbc_sha",
        "s2n_dhe_rsa_with_3des_ede_cbc_sha",
        "s2n_rsa_with_aes_128_cbc_sha",
        "s2n_dhe_rsa_with_aes_128_cbc_sha",
        "s2n_rsa_with_aes_256_cbc_sha",
        "s2n_dhe_rsa_with_aes_256_cbc_sha",
        "s2n_rsa_with_aes_128_cbc_sha256",
        "s2n_rsa_with_aes_256_cbc_sha256",
        "s2n_dhe_rsa_with_aes_128_cbc_sha256",
        "s2n_dhe_rsa_with_aes_256_cbc_sha256",
        "s2n_rsa_with_aes_128_gcm_sha256",
        "s2n_rsa_with_aes_256_gcm_sha384",
        "s2n_dhe_rsa_with_aes_128_gcm_sha256",
        "s2n_ecdhe_rsa_with_rc4_128_sha",
        "s2n_ecdhe_rsa_with_3des_ede_cbc_sha",
        "s2n_ecdhe_rsa_with_aes_128_cbc_sha",
        "s2n_ecdhe_rsa_with_aes_256_cbc_sha",

        "s2n_ecdhe_rsa_with_aes_256_cbc_sha384",
        "s2n_ecdhe_rsa_with_aes_128_gcm_sha256",
        "s2n_ecdhe_rsa_with_aes_256_gcm_sha384",
        "s2n_ecdhe_rsa_with_chacha20_poly1305_sha256",
        "s2n_dhe_rsa_with_chacha20_poly1305_sha256",
        "s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384",
        "s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384",
        "s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384",
        "s2n_ecdhe_ecdsa_with_aes_128_cbc_sha",
        "s2n_ecdhe_ecdsa_with_aes_256_cbc_sha",
        "s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256",
        "s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384",
        "s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256",
        "s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384",
        "s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256"
};

struct s2n_cipher_suite *all_suites[] = {
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_gcm_sha384,
        &s2n_rsa_with_rc4_128_md5,                      /* 0x00,0x04 */
        &s2n_rsa_with_rc4_128_sha,                      /* 0x00,0x05 */
        &s2n_rsa_with_3des_ede_cbc_sha,                 /* 0x00,0x0A */
        &s2n_dhe_rsa_with_3des_ede_cbc_sha,             /* 0x00,0x16 */
        &s2n_rsa_with_aes_128_cbc_sha,                  /* 0x00,0x2F */
        &s2n_dhe_rsa_with_aes_128_cbc_sha,              /* 0x00,0x33 */
        &s2n_rsa_with_aes_256_cbc_sha,                  /* 0x00,0x35 */
        &s2n_dhe_rsa_with_aes_256_cbc_sha,              /* 0x00,0x39 */
        &s2n_rsa_with_aes_128_cbc_sha256,               /* 0x00,0x3C */
        &s2n_rsa_with_aes_256_cbc_sha256,               /* 0x00,0x3D */
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,           /* 0x00,0x67 */
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,           /* 0x00,0x6B */
        &s2n_rsa_with_aes_128_gcm_sha256,               /* 0x00,0x9C */
        &s2n_rsa_with_aes_256_gcm_sha384,               /* 0x00,0x9D */
        &s2n_dhe_rsa_with_aes_128_gcm_sha256,           /* 0x00,0x9E */
        /* 0x00,0x9F */
        &s2n_ecdhe_rsa_with_rc4_128_sha,                /* 0xC0,0x11 */
        &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,           /* 0xC0,0x12 */
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha,            /* 0xC0,0x13 */
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,            /* 0xC0,0x14 */

        /* 0xC0,0x27 */
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,         /* 0xC0,0x28 */


        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,         /* 0xC0,0x2F */
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,         /* 0xC0,0x30 */
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,   /* 0xCC,0xA8 */

        &s2n_dhe_rsa_with_chacha20_poly1305_sha256,     /* 0xCC,0xAA */
        &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x04 */
        &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x08 */
        &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,   /* 0xFF,0x0C */

        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
};

#define BENCHMARK_SUCCESS( condition ) __S2N_ENSURE((condition) >= S2N_SUCCESS, state.SkipWithError(#condition ", benchmark did not pass when expected too"))

#define BENCHMARK_FAILURE( condition ) __S2N_ENSURE((condition) < S2N_SUCCESS, state.SkipWithError(#condition ", benchmark did pass when expected not too"))


int calls_to_s2n_negotiate = 0;
struct s2n_blob r;
int rc;

static const uint8_t hex_inverse[256] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 255, 255, 255, 255, 255, 255,
        255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

struct verify_data {
    const char *trusted_host;
};

void print_s2n_error(const char *app_error)
{
    fprintf(stderr, "[%d] %s: '%s' : '%s'\n", getpid(), app_error, s2n_strerror(s2n_errno, "EN"),
            s2n_strerror_debug(s2n_errno, "EN"));
}

static int wait_for_event(int fd, s2n_blocked_status blocked)
{
    struct pollfd reader = {fd, 0};

    switch (blocked) {
        case S2N_NOT_BLOCKED:
            return S2N_SUCCESS;
        case S2N_BLOCKED_ON_READ:
            reader.events |= POLLIN;
            break;
        case S2N_BLOCKED_ON_WRITE:
            reader.events |= POLLOUT;
            break;
        case S2N_BLOCKED_ON_EARLY_DATA:
        case S2N_BLOCKED_ON_APPLICATION_INPUT:
            // This case is not encountered by the s2nc/s2nd applications,
             // but is detected for completeness
            return S2N_SUCCESS;
    }

    if (poll(&reader, 1, -1) < 0) {
        fprintf(stderr, "Failed to poll connection: %s\n", strerror(errno));
        //state.SkipWithError("Poll Failed\n");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    return S2N_SUCCESS;
}

int key_log_callback(void *file, struct s2n_connection *conn, uint8_t *logline, size_t len)
{
    if (fwrite(logline, 1, len, (FILE *)file) != len) {
        return S2N_FAILURE;
    }

    if (fprintf((FILE *)file, "\n") < 0) {
        return S2N_FAILURE;
    }

    return fflush((FILE *)file);
}

int early_data_send(struct s2n_connection *conn, uint8_t *data, uint32_t len)
{
    s2n_blocked_status blocked = (s2n_blocked_status)0;
    ssize_t total_data_sent = 0;
    ssize_t data_sent = 0;
    bool client_success = 0;
    do {
        client_success = (s2n_send_early_data(conn, data + total_data_sent,
                                              len - total_data_sent, &data_sent, &blocked) >= S2N_SUCCESS);
        total_data_sent += data_sent;
    } while (total_data_sent < len && !client_success);

    return S2N_SUCCESS;
}


int s2n_str_hex_to_bytes(const unsigned char *hex, uint8_t *out_bytes, uint32_t max_out_bytes_len)
{
    GUARD_EXIT_NULL(hex);
    GUARD_EXIT_NULL(out_bytes);

    uint32_t len_with_spaces = strlen((const char *)hex);
    size_t i = 0, j = 0;
    while (j < len_with_spaces) {
        if (hex[j] == ' ') {
            j++;
            continue;
        }

        uint8_t high_nibble = hex_inverse[hex[j]];
        if (high_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        uint8_t low_nibble = hex_inverse[hex[j + 1]];
        if (low_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        if(max_out_bytes_len < i) {
            fprintf(stderr, "Insufficient memory for bytes buffer, try increasing the allocation size\n");
            return S2N_FAILURE;
        }
        out_bytes[i] = high_nibble << 4 | low_nibble;

        i++;
        j+=2;
    }

    return S2N_SUCCESS;
}

static int s2n_get_psk_hmac_alg(s2n_psk_hmac *psk_hmac, char *hmac_str)
{
    GUARD_EXIT_NULL(psk_hmac);
    GUARD_EXIT_NULL(hmac_str);

    if (strcmp(hmac_str, "SHA256") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA256;
    } else if (strcmp(hmac_str, "SHA384") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA384;
    } else {
        return S2N_FAILURE;
    }
    return S2N_SUCCESS;
}

static int s2n_setup_external_psk(struct s2n_psk **psk, char *params)
{
    GUARD_EXIT_NULL(psk);
    GUARD_EXIT_NULL(params);

    size_t token_idx = 0;
    for (char *token = strtok(params, ","); token != NULL; token = strtok(NULL, ","), token_idx++) {
        switch (token_idx) {
            case 0:
                GUARD_EXIT(s2n_psk_set_identity(*psk, (const uint8_t *)token, strlen(token)),
                           "Error setting psk identity\n");
                break;
            case 1: {
                uint32_t max_secret_len = strlen(token)/2;
                uint8_t *secret = (uint8_t*)malloc(max_secret_len);
                GUARD_EXIT_NULL(secret);
                GUARD_EXIT(s2n_str_hex_to_bytes((const unsigned char *)token, secret, max_secret_len), "Error converting hex-encoded psk secret to bytes\n");
                GUARD_EXIT(s2n_psk_set_secret(*psk, secret, max_secret_len), "Error setting psk secret\n");
                free(secret);
            }
                break;
            case 2: {
                s2n_psk_hmac psk_hmac_alg = (s2n_psk_hmac)0;
                GUARD_EXIT(s2n_get_psk_hmac_alg(&psk_hmac_alg, token), "Invalid psk hmac algorithm\n");
                GUARD_EXIT(s2n_psk_set_hmac(*psk, psk_hmac_alg), "Error setting psk hmac algorithm\n");
            }
                break;
            default:
                break;
        }
    }

    return S2N_SUCCESS;
}

int s2n_setup_external_psk_list(struct s2n_connection *conn, char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH], size_t psk_list_len)
{
    GUARD_EXIT_NULL(conn);
    GUARD_EXIT_NULL(psk_optarg_list);

    for (size_t i = 0; i < psk_list_len; i++) {
        struct s2n_psk *psk = s2n_external_psk_new();
        GUARD_EXIT_NULL(psk);
        GUARD_EXIT(s2n_setup_external_psk(&psk, psk_optarg_list[i]), "Error setting external PSK parameters\n");
        GUARD_EXIT(s2n_connection_append_psk(conn, psk), "Error appending psk to the connection\n");
        GUARD_EXIT(s2n_psk_free(&psk), "Error freeing psk\n");
    }
    return S2N_SUCCESS;
}


int negotiate(struct s2n_connection *conn, int fd, benchmark::State& state)
{
    s2n_blocked_status blocked;
    calls_to_s2n_negotiate += 1;
    int s2n_ret;
    state.ResumeTiming();
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    state.PauseTiming();
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    while (s2n_ret != S2N_SUCCESS) {
        calls_to_s2n_negotiate += 1;
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }

        state.SkipWithError("Negotiate Failed\n");
    }
    int client_hello_version;
    int client_protocol_version;
    int server_protocol_version;
    int actual_protocol_version;

    if ((client_hello_version = s2n_connection_get_client_hello_version(conn)) < 0) {
        fprintf(stderr, "Could not get client hello version\n");
        POSIX_BAIL(S2N_ERR_CLIENT_HELLO_VERSION);
    }
    if ((client_protocol_version = s2n_connection_get_client_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get client protocol version\n");
        POSIX_BAIL(S2N_ERR_CLIENT_PROTOCOL_VERSION);
    }
    if ((server_protocol_version = s2n_connection_get_server_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get server protocol version\n");
        POSIX_BAIL(S2N_ERR_SERVER_PROTOCOL_VERSION);
    }
    if ((actual_protocol_version = s2n_connection_get_actual_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get actual protocol version\n");
        POSIX_BAIL(S2N_ERR_ACTUAL_PROTOCOL_VERSION);
    }
    if(DEBUG_PRINT) {
        printf("CONNECTED:\n");
        printf("Handshake: %s\n", s2n_connection_get_handshake_type_name(conn));
        printf("Client hello version: %d\n", client_hello_version);
        printf("Client protocol version: %d\n", client_protocol_version);
        printf("Server protocol version: %d\n", server_protocol_version);
        printf("Actual protocol version: %d\n", actual_protocol_version);
    }

    if (s2n_get_server_name(conn)) {
        if(DEBUG_PRINT)
            printf("Server name: %s\n", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        if(DEBUG_PRINT)
            printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    if(DEBUG_PRINT)
        printf("Curve: %s\n", s2n_connection_get_curve(conn));
    if(DEBUG_PRINT)
        printf("KEM: %s\n", s2n_connection_get_kem_name(conn));
    if(DEBUG_PRINT)
        printf("KEM Group: %s\n", s2n_connection_get_kem_group_name(conn));

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    if(DEBUG_CIPHER)
        printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));

    bool session_resumed = s2n_connection_is_session_resumed(conn);
    if (session_resumed) {
        if(DEBUG_PRINT)
            printf("Resumed session\n");
    }

    uint16_t identity_length = 0;
    GUARD_EXIT(s2n_connection_get_negotiated_psk_identity_length(conn, &identity_length), "Error getting negotiated psk identity length from the connection\n");
    if (identity_length != 0 && !session_resumed) {
        uint8_t *identity = (uint8_t*)malloc(identity_length);
        GUARD_EXIT_NULL(identity);
        GUARD_EXIT(s2n_connection_get_negotiated_psk_identity(conn, identity, identity_length), "Error getting negotiated psk identity from the connection\n");
        if(DEBUG_PRINT)
            printf("Negotiated PSK identity: %s\n", identity);
        free(identity);
    }

    s2n_early_data_status_t early_data_status = (s2n_early_data_status_t)0;
    GUARD_EXIT(s2n_connection_get_early_data_status(conn, &early_data_status), "Error getting early data status");
    const char *status_str = NULL;
    switch(early_data_status) {
        case S2N_EARLY_DATA_STATUS_OK: status_str = "IN PROGRESS"; break;
        case S2N_EARLY_DATA_STATUS_NOT_REQUESTED: status_str = "NOT REQUESTED"; break;
        case S2N_EARLY_DATA_STATUS_REJECTED: status_str = "REJECTED"; break;
        case S2N_EARLY_DATA_STATUS_END: status_str = "ACCEPTED"; break;
    }
    GUARD_EXIT_NULL(status_str);
    if(DEBUG_PRINT)
        printf("Early Data status: %s\n", status_str);

    if(DEBUG_PRINT)
        printf("s2n is ready\n");
    return 0;
}

static uint8_t unsafe_verify_host(const char *host_name, size_t host_name_len, void *data) {
    struct verify_data *verify_data = (struct verify_data *)data;

    if (host_name_len > 2 && host_name[0] == '*' && host_name[1] == '.') {
        const char *suffix = strstr(verify_data->trusted_host, ".");
        return (uint8_t)(strcasecmp(suffix, host_name + 1) == 0);
    }

    if (strcasecmp(host_name, "localhost") == 0 || strcasecmp(host_name, "127.0.0.1") == 0) {
        return (uint8_t) (strcasecmp(verify_data->trusted_host, "localhost") == 0
                          || strcasecmp(verify_data->trusted_host, "127.0.0.1") == 0);
    }

    return (uint8_t) (strcasecmp(host_name, verify_data->trusted_host) == 0);
}


static void ClientBenchmark(benchmark::State& state) {
    struct addrinfo hints, *ai_list, *ai;
    int add, sockfd = 0;
    const char *server_name = "localhost";
    const char *host = "localhost";
    const char *port = "8000";
    const char *cipher_prefs = "test_all_tls12";
    s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
    uint16_t mfl_value = 0;
    int use_corked_io = 1;
    //int keyshares_count = 0;
    //char keyshares[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT][S2N_MAX_ECC_CURVE_NAME_LENGTH];
    char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
    size_t psk_list_len = 0;
    char *early_data = NULL;
    uint8_t insecure = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((add = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(add));
        printf("Error: %d\n", add);
        printf("Errno: %s\n", strerror(errno));
        exit(1);
    }

    for (auto _ : state) {
        state.PauseTiming();

        int connected = 0;
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
            if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
                continue;
            }

            if (connect(sockfd, ai->ai_addr, ai->ai_addrlen) == -1) {
                close(sockfd);
                continue;
            }

            connected = 1;
            if(DEBUG_PRINT)
                printf("Connected to s2nd\n");
            break;
        }
        if (connected == 0) {
            fprintf(stderr, "Failed to connect to %s:%s\n", host, port);
            printf("Error: %s\n", strerror(errno));
            exit(1);
        }

        struct s2n_config *config = s2n_config_new();

        struct verify_data *unsafe_verify_data = (verify_data*)malloc(sizeof(verify_data));;

        if (config == NULL) {
            print_s2n_error("Error getting new config");
            exit(1);
        }
        if(DEBUG_CIPHER)
            printf("Cipher preference = %s\n", cipher_prefs);


        //GUARD_EXIT(s2n_config_set_cipher_preferences(config, cipher_prefs), "Error setting cipher prefs");

        struct s2n_cipher_suite *cipher_suites_benchmark[] = {
                all_suites[state.range(0)]
        };

        const struct s2n_cipher_preferences cipher_preferences_benchmark = {
                s2n_array_len(cipher_suites_benchmark),
                cipher_suites_benchmark,
        };

        const struct s2n_security_policy security_policy_benchmark = {
                S2N_SSLv3,
                &cipher_preferences_benchmark,
                &kem_preferences_kms_pq_tls_1_0_2020_07,
                &s2n_signature_preferences_20201021,
                NULL,
                &s2n_ecc_preferences_20201021,
        };

        config->security_policy = &security_policy_benchmark;



        GUARD_EXIT(s2n_config_set_status_request_type(config, type), "OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");

        if (s2n_config_set_verify_host_callback(config, unsafe_verify_host, unsafe_verify_data) < 0) {
            print_s2n_error("Error setting host name verification function.");
        }

        if (type == S2N_STATUS_REQUEST_OCSP) {
            if(s2n_config_set_check_stapled_ocsp_response(config, 1)) {
                print_s2n_error("OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");
            }
        }

        unsafe_verify_data->trusted_host = host;

        uint8_t mfl_code = 0;
        if (mfl_value > 0) {
            switch(mfl_value) {
                case 512:
                    mfl_code = S2N_TLS_MAX_FRAG_LEN_512;
                    break;
                case 1024:
                    mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;
                    break;
                case 2048:
                    mfl_code = S2N_TLS_MAX_FRAG_LEN_2048;
                    break;
                case 4096:
                    mfl_code = S2N_TLS_MAX_FRAG_LEN_4096;
                    break;
                default:
                    fprintf(stderr, "Invalid maximum fragment length value\n");
                    exit(1);
            }
        }

        GUARD_EXIT(s2n_config_send_max_fragment_length(config, (s2n_max_frag_len)mfl_code), "Error setting maximum fragment length");


        if (insecure) {
            GUARD_EXIT(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
        }

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);

        if (conn == NULL) {
            print_s2n_error("Error getting new connection");
            exit(1);
        }

        GUARD_EXIT(s2n_connection_set_config(conn, config), "Error setting configuration");

        GUARD_EXIT(s2n_set_server_name(conn, server_name), "Error setting server name");

        GUARD_EXIT(s2n_connection_set_fd(conn, sockfd) , "Error setting file descriptor");

        GUARD_EXIT(s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL), "Error setting ClientAuth optional");

        if (use_corked_io) {
            GUARD_EXIT(s2n_connection_use_corked_io(conn), "Error setting corked io");
        }

        /*
        for (size_t i = 0; i < (size_t)keyshares_count; i++) {
            if (keyshares[i]) {
                GUARD_EXIT(s2n_connection_set_keyshare_by_name_for_testing(conn, keyshares[i]), "Error setting keyshares to generate");
            }
        }
         */

        GUARD_EXIT(s2n_setup_external_psk_list(conn, psk_optarg_list, psk_list_len), "Error setting external psk list");

        if (negotiate(conn, sockfd, state) != 0) {
            state.SkipWithError("Negotiate Failed\n");
            if(DEBUG_PRINT)
                printf("Error in negotiate!\n");
        }

        if(DEBUG_PRINT)
            printf("Connected to %s:%s\n", host, port);

        GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

        s2n_blocked_status blocked;
        int shutdown_rc = s2n_shutdown(conn, &blocked);
        if (shutdown_rc == -1 && blocked != S2N_BLOCKED_ON_READ) {
            fprintf(stderr, "Unexpected error during shutdown: '%s'\n", s2n_strerror(s2n_errno, "NULL"));
            exit(1);
        }

        GUARD_EXIT(s2n_connection_free(conn), "Error freeing connection");

        GUARD_EXIT(s2n_config_free(config), "Error freeing configuration");

        free(unsafe_verify_data);

        close(sockfd);

        state.ResumeTiming();
    }

    free(early_data);
    freeaddrinfo(ai_list);

}

BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[0])->Iterations(ITERATIONS)->Arg(0);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[1])->Iterations(ITERATIONS)->Arg(1);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[2])->Iterations(ITERATIONS)->Arg(2);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[3])->Iterations(ITERATIONS)->Arg(3);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[4])->Iterations(ITERATIONS)->Arg(4);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[5])->Iterations(ITERATIONS)->Arg(5);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[6])->Iterations(ITERATIONS)->Arg(6);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[7])->Iterations(ITERATIONS)->Arg(7);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[8])->Iterations(ITERATIONS)->Arg(8);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[9])->Iterations(ITERATIONS)->Arg(9);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[10])->Iterations(ITERATIONS)->Arg(10);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[11])->Iterations(ITERATIONS)->Arg(11);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[12])->Iterations(ITERATIONS)->Arg(12);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[13])->Iterations(ITERATIONS)->Arg(13);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[14])->Iterations(ITERATIONS)->Arg(14);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[15])->Iterations(ITERATIONS)->Arg(15);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[16])->Iterations(ITERATIONS)->Arg(16);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[17])->Iterations(ITERATIONS)->Arg(17);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[18])->Iterations(ITERATIONS)->Arg(18);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[19])->Iterations(ITERATIONS)->Arg(19);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[20])->Iterations(ITERATIONS)->Arg(20);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[21])->Iterations(ITERATIONS)->Arg(21);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[22])->Iterations(ITERATIONS)->Arg(22);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[23])->Iterations(ITERATIONS)->Arg(23);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[24])->Iterations(ITERATIONS)->Arg(24);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[25])->Iterations(ITERATIONS)->Arg(25);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[26])->Iterations(ITERATIONS)->Arg(26);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[27])->Iterations(ITERATIONS)->Arg(27);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[28])->Iterations(ITERATIONS)->Arg(28);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[29])->Iterations(ITERATIONS)->Arg(29);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[30])->Iterations(ITERATIONS)->Arg(30);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[31])->Iterations(ITERATIONS)->Arg(31);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[32])->Iterations(ITERATIONS)->Arg(32);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[33])->Iterations(ITERATIONS)->Arg(33);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[34])->Iterations(ITERATIONS)->Arg(34);
BENCHMARK(ClientBenchmark)->Name(suite_names_benchmark[35])->Iterations(ITERATIONS)->Arg(35);

/*
 * Change sizes to 1KB, 10KB, 1MB
 */

int main(int argc, char** argv) {
    rc = s2n_init();
    ::benchmark::Initialize(&argc, argv);

    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();
    s2n_cleanup();

}
