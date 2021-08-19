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

#include "tests/benchmark/utils/s2n_negotiate_client_benchmark.h"
#include "tests/benchmark/utils/shared_info.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <poll.h>
#include <vector>
#include <stdlib.h>

extern "C" {
#include "bin/common.h"
#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
}

static int setup_socket(struct addrinfo hints, struct addrinfo *ai_list, struct addrinfo *ai) {
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int add = 0;

    if ((add = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\nError: %d\nErrno: %s\n", gai_strerror(add), add, strerror(errno));
        return -1;
    }

    bool connected = false;
    while (!connected) {
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
            if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
                continue;
            }
            if (connect(sockfd, ai->ai_addr, ai->ai_addrlen) == -1) {
                close(sockfd);
                continue;
            }
            connected = true;
            if (DEBUG_PRINT) {
                printf("Connected to s2nd\n");
            }
            break;
        }
    }

    freeaddrinfo(ai_list);
    GUARD_EXIT(sockfd, "Socket setup failed\n");
    return 0;
}

static void client_handshake(benchmark::State& state, bool warmup, struct s2n_connection *conn) {
    struct verify_data *unsafe_verify_data = (verify_data *) malloc(sizeof(verify_data));
    s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;

    GUARD_EXIT(s2n_config_set_status_request_type(config, type),
               "OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");

    if (s2n_config_set_verify_host_callback(config, unsafe_verify_host, unsafe_verify_data) != S2N_SUCCESS) {
        print_s2n_error("Error setting host name verification function.");
    }

    unsafe_verify_data->trusted_host = host;

    if (!conn_settings.insecure) {
        GUARD_EXIT(s2n_config_add_pem_to_trust_store(config, rsa_certificate_chain), "Failing RSA public key");
        GUARD_EXIT(s2n_config_add_pem_to_trust_store(config, ecdsa_certificate_chain), "Failing ECDSA public key");

    }
    else {
        GUARD_EXIT(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
    }

    if (conn == NULL) {
        print_s2n_error("Error getting new connection");
        exit(1);
    }

    GUARD_EXIT(s2n_connection_set_config(conn, config), "Error setting configuration");

    GUARD_EXIT(s2n_set_server_name(conn, host), "Error setting server name");

    GUARD_EXIT(s2n_connection_set_fd(conn, sockfd), "Error setting file descriptor");

    GUARD_EXIT(s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL),
               "Error setting ClientAuth optional");

    if (conn_settings.use_corked_io) {
        GUARD_EXIT(s2n_connection_use_corked_io(conn), "Error setting corked io");
    }

    if (benchmark_negotiate(conn, sockfd, state, warmup) != S2N_SUCCESS) {
        state.SkipWithError("Negotiate Failed\n");
        if (DEBUG_PRINT) {
            printf("Error in negotiate!\n");
        }
    }

    if (DEBUG_PRINT) {
        printf("Connected to %s:%s\n", host, port);
    }

    GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

    s2n_blocked_status blocked;
    int shutdown_rc = s2n_shutdown(conn, &blocked);
    if (shutdown_rc == S2N_FAILURE && blocked != S2N_BLOCKED_ON_READ) {
        fprintf(stderr, "Unexpected error during shutdown: '%s'\n", s2n_strerror(s2n_errno, "NULL"));
        exit(1);
    }

    GUARD_EXIT(s2n_connection_wipe(conn), "Error wiping connection");

    free(unsafe_verify_data);
}

static void benchmark_single_suite_client(benchmark::State& state) {
    config = s2n_config_new();
    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
    size_t WARMUP_ITERS = state.range(1);

    GUARD_EXIT_NULL(config);

    /* In order to specify each cipher suite from the cipher_preferences_test_all_tls12
     * list, a custom cipher_suite list must be created with only one cipher suite. In
     * order to use this new list, a cipher preference and security policy must also be
     * created */
    struct s2n_cipher_suite *cipher_suites_benchmark[] = {
            all_suites[state.range(0)]
    };

    const struct s2n_cipher_preferences cipher_preferences_benchmark = {
            1, /* count */
            cipher_suites_benchmark, /* suites */
    };

    const struct s2n_security_policy security_policy_benchmark = {
            S2N_SSLv3, /* minimum_protocol_version */
            &cipher_preferences_benchmark, /* cipher_preferences */
            &kem_preferences_kms_pq_tls_1_0_2020_07, /* kem_preferences */
            &s2n_signature_preferences_20201021, /* signature_preferences */
            NULL, /* certificate_signature_preferences */
            &s2n_ecc_preferences_20201021, /* ecc_preferences */
    };

    config->security_policy = &security_policy_benchmark;

    for (size_t i = 0; i < WARMUP_ITERS; i++) {
        client_handshake(state, true, conn);
    }
    for (auto _ : state) {
        state.PauseTiming();
        client_handshake(state, false, conn);
    }
    GUARD_EXIT(s2n_config_free(config), "Error freeing configuration");
    GUARD_EXIT(s2n_connection_free(conn), "Error freeing connection");
}

int start_negotiate_benchmark_client(int argc, char** argv) {
    int use_corked_io = 0;
    int insecure = 1;
    conn_settings = {0};
    char bench_format[100] = "--benchmark_out_format=";
    char file_prefix[100];
    size_t WARMUP_ITERS = 1;
    size_t ITERATIONS = 1;
    struct addrinfo hints, *ai_list, *ai;

    argument_parse(argc, argv, use_corked_io, insecure, bench_format, file_prefix, WARMUP_ITERS, ITERATIONS);

    char bench_out[100] = "--benchmark_out=client_";
    strcat(bench_out, file_prefix);
    argc += 2;

    std::vector<char*> argv_bench(argv, argv + argc);
    argv_bench.push_back(bench_out);
    argv_bench.push_back(bench_format);
    argv_bench.push_back(nullptr);

    conn_settings.use_corked_io = use_corked_io;
    conn_settings.insecure = insecure;

    s2n_init();

    GUARD_EXIT(setup_socket(hints, ai_list, ai), "setup failed");

    for (size_t current_suite = 0; current_suite < num_suites; current_suite++) {
        char bench_name[80];
        strcpy(bench_name, "Client: ");
        strcat(bench_name, all_suites[current_suite]->name);

        benchmark::RegisterBenchmark(bench_name, benchmark_single_suite_client)->Repetitions(ITERATIONS)
        ->ReportAggregatesOnly()->Iterations(1)->Args({(long int)current_suite, (long int)WARMUP_ITERS});
    }
    ::benchmark::Initialize(&argc, argv_bench.data());
    ::benchmark::RunSpecifiedBenchmarks();
    s2n_cleanup();
    close(sockfd);
    return 0;
}
