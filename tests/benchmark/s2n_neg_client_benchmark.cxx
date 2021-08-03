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
#include <tests/benchmark/s2n_neg_client_benchmark.h>
#include <benchmark/benchmark.h>
#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <string>

#include <vector>
#define STDIO_BUFSIZE  10240

extern "C" {

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
}

//able to be modified when running benchmark
static int DEBUG_PRINT = 0;
static int DEBUG_CIPHER = 0;
static unsigned int ITERATIONS = 50;

extern int rc;

const char *host = "localhost";
const char *port = "8000";
struct addrinfo hints, *ai_list, *ai;
int add, sockfd = 0;
const char *server_name = "localhost";
const char *cipher_prefs = "test_all_tls12";
s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
int use_corked_io = 0;
char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
size_t psk_list_len = 0;
uint8_t insecure = 1;

static struct s2n_cipher_suite *all_suites[] = {
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


static unsigned int calls_to_s2n_negotiate = 0;
struct s2n_blob r;
int rc;


struct verify_data {
    const char *trusted_host;
};

static int my_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state)
{
    s2n_blocked_status blocked;
    calls_to_s2n_negotiate += 1;
    int s2n_ret;
    state.ResumeTiming();
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    state.PauseTiming();
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    if (s2n_ret != S2N_SUCCESS) {
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

    if(DEBUG_PRINT) {
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

        printf("CONNECTED:\n");
        printf("Handshake: %s\n", s2n_connection_get_handshake_type_name(conn));
        printf("Client hello version: %d\n", client_hello_version);
        printf("Client protocol version: %d\n", client_protocol_version);
        printf("Server protocol version: %d\n", server_protocol_version);
        printf("Actual protocol version: %d\n", actual_protocol_version);
        printf("Server name: %s\n", s2n_get_server_name(conn));
        printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
        printf("Curve: %s\n", s2n_connection_get_curve(conn));
        printf("KEM: %s\n", s2n_connection_get_kem_name(conn));
        printf("KEM Group: %s\n", s2n_connection_get_kem_group_name(conn));
    }


    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    if(DEBUG_CIPHER) {
        printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));
    }

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

static void setup_config() {
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((add = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(add));
        printf("Error: %d\n", add);
        printf("Errno: %s\n", strerror(errno));
        exit(1);
    }
    return;
}

static void ClientBenchmark(benchmark::State& state) {
    setup_config();
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
            if(DEBUG_PRINT) {
                printf("Connected to s2nd\n");
            }
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
        if(DEBUG_CIPHER) {
            printf("Cipher preference = %s\n", cipher_prefs);
        }

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

        GUARD_EXIT(s2n_setup_external_psk_list(conn, psk_optarg_list, psk_list_len), "Error setting external psk list");

        if (my_negotiate(conn, sockfd, state) != 0) {
            state.SkipWithError("Negotiate Failed\n");
            if(DEBUG_PRINT) {
                printf("Error in negotiate!\n");
            }
        }

        if(DEBUG_PRINT) {
            printf("Connected to %s:%s\n", host, port);
        }

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
    }

    freeaddrinfo(ai_list);

}

BENCHMARK(ClientBenchmark)->Name(all_suites[0]->name)->Iterations(ITERATIONS)->Arg(0);
BENCHMARK(ClientBenchmark)->Name(all_suites[1]->name)->Iterations(ITERATIONS)->Arg(1);
BENCHMARK(ClientBenchmark)->Name(all_suites[2]->name)->Iterations(ITERATIONS)->Arg(2);
BENCHMARK(ClientBenchmark)->Name(all_suites[3]->name)->Iterations(ITERATIONS)->Arg(3);
BENCHMARK(ClientBenchmark)->Name(all_suites[4]->name)->Iterations(ITERATIONS)->Arg(4);
BENCHMARK(ClientBenchmark)->Name(all_suites[5]->name)->Iterations(ITERATIONS)->Arg(5);
BENCHMARK(ClientBenchmark)->Name(all_suites[6]->name)->Iterations(ITERATIONS)->Arg(6);
BENCHMARK(ClientBenchmark)->Name(all_suites[7]->name)->Iterations(ITERATIONS)->Arg(7);
BENCHMARK(ClientBenchmark)->Name(all_suites[8]->name)->Iterations(ITERATIONS)->Arg(8);
BENCHMARK(ClientBenchmark)->Name(all_suites[9]->name)->Iterations(ITERATIONS)->Arg(9);
BENCHMARK(ClientBenchmark)->Name(all_suites[10]->name)->Iterations(ITERATIONS)->Arg(10);
BENCHMARK(ClientBenchmark)->Name(all_suites[11]->name)->Iterations(ITERATIONS)->Arg(11);
BENCHMARK(ClientBenchmark)->Name(all_suites[12]->name)->Iterations(ITERATIONS)->Arg(12);
BENCHMARK(ClientBenchmark)->Name(all_suites[13]->name)->Iterations(ITERATIONS)->Arg(13);
BENCHMARK(ClientBenchmark)->Name(all_suites[14]->name)->Iterations(ITERATIONS)->Arg(14);
BENCHMARK(ClientBenchmark)->Name(all_suites[15]->name)->Iterations(ITERATIONS)->Arg(15);
BENCHMARK(ClientBenchmark)->Name(all_suites[16]->name)->Iterations(ITERATIONS)->Arg(16);
BENCHMARK(ClientBenchmark)->Name(all_suites[17]->name)->Iterations(ITERATIONS)->Arg(17);
BENCHMARK(ClientBenchmark)->Name(all_suites[18]->name)->Iterations(ITERATIONS)->Arg(18);
BENCHMARK(ClientBenchmark)->Name(all_suites[19]->name)->Iterations(ITERATIONS)->Arg(19);
BENCHMARK(ClientBenchmark)->Name(all_suites[20]->name)->Iterations(ITERATIONS)->Arg(20);
BENCHMARK(ClientBenchmark)->Name(all_suites[21]->name)->Iterations(ITERATIONS)->Arg(21);
BENCHMARK(ClientBenchmark)->Name(all_suites[22]->name)->Iterations(ITERATIONS)->Arg(22);
BENCHMARK(ClientBenchmark)->Name(all_suites[23]->name)->Iterations(ITERATIONS)->Arg(23);
BENCHMARK(ClientBenchmark)->Name(all_suites[24]->name)->Iterations(ITERATIONS)->Arg(24);
BENCHMARK(ClientBenchmark)->Name(all_suites[25]->name)->Iterations(ITERATIONS)->Arg(25);
BENCHMARK(ClientBenchmark)->Name(all_suites[26]->name)->Iterations(ITERATIONS)->Arg(26);
BENCHMARK(ClientBenchmark)->Name(all_suites[27]->name)->Iterations(ITERATIONS)->Arg(27);
BENCHMARK(ClientBenchmark)->Name(all_suites[28]->name)->Iterations(ITERATIONS)->Arg(28);
BENCHMARK(ClientBenchmark)->Name(all_suites[29]->name)->Iterations(ITERATIONS)->Arg(29);
BENCHMARK(ClientBenchmark)->Name(all_suites[30]->name)->Iterations(ITERATIONS)->Arg(30);
BENCHMARK(ClientBenchmark)->Name(all_suites[31]->name)->Iterations(ITERATIONS)->Arg(31);
BENCHMARK(ClientBenchmark)->Name(all_suites[32]->name)->Iterations(ITERATIONS)->Arg(32);
BENCHMARK(ClientBenchmark)->Name(all_suites[33]->name)->Iterations(ITERATIONS)->Arg(33);
BENCHMARK(ClientBenchmark)->Name(all_suites[34]->name)->Iterations(ITERATIONS)->Arg(34);
BENCHMARK(ClientBenchmark)->Name(all_suites[35]->name)->Iterations(ITERATIONS)->Arg(35);

/*
 * Change sizes to 1KB, 10KB, 1MB
 */

int Client::start_benchmark_client(int argc, char** argv) {
    rc = s2n_init();

    if(argc > 1){
        host = argv[1];
        port = argv[2];
        ITERATIONS = atoi(argv[3]);
        DEBUG_PRINT = atoi(argv[4]);
        DEBUG_CIPHER = atoi(argv[5]);
        use_corked_io = atoi(argv[6]);
    }
    ::benchmark::Initialize(&argc, argv);

    ::benchmark::RunSpecifiedBenchmarks();
    s2n_cleanup();
    return 0;
}
