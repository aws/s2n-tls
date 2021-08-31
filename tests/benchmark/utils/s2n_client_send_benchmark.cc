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

#include "tests/benchmark/utils/s2n_client_send_benchmark.h"
#include "tests/benchmark/utils/shared_info.h"
#include "utils/s2n_safety.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <sys/fcntl.h>

extern "C" {
#include "bin/common.h"
#include "tls/s2n_connection.h"
}

int send_data(struct s2n_connection *conn, benchmark::State& state, bool warmup) {
    errno = 0;
    s2n_blocked_status blocked;
    int number_bytes_receiving = state.range(0);
    uint8_t* send;
    send = (uint8_t*)malloc(number_bytes_receiving);
    RAND_bytes(send, number_bytes_receiving);

    /*
     * s2n_send may only send partial data through. s2n_send should be repeatedly
     * called until all data has been send and s2n is no longer blocked.
     */
    int written = 0;
    do {
        int written_bytes = 0;
        if (!warmup) {
            state.ResumeTiming();
        }
        benchmark::DoNotOptimize(written_bytes = s2n_send(conn, send + written, number_bytes_receiving - written, &blocked));
        if (!warmup) {
            state.PauseTiming();
        }
        if (written_bytes < 0) {
            fprintf(stderr, "Error writing to connection: '%s' %d\n", s2n_strerror(s2n_errno, "EN"),
                    s2n_connection_get_alert(conn));
            exit(1);
        }
        written += written_bytes;
    } while (blocked != S2N_NOT_BLOCKED);
    free(send);
    return 0;
}

static int setup_socket(int& sockfd) {
    struct addrinfo hints = {};
    struct addrinfo *ai = nullptr;
    struct addrinfo *ai_list = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    GUARD_EXIT(getaddrinfo(host, port, &hints, &ai_list), "getaddrinfo error\n");

    bool connected = false;
    while (!connected) {
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
            if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) { continue; }
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
    return 0;
}

static void benchmark_send_single_suite_client(benchmark::State& state) {
    config = s2n_config_new();
    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
    size_t warmup_iters = state.range(2);
    int sockfd = state.range(3);

    GUARD_EXIT_NULL(config);

    /* In order to specify each cipher suite from the cipher_preferences_test_all_tls12
     * list, a custom cipher_suite list must be created with only one cipher suite. In
     * order to use this new list, a cipher preference and security policy must also be
     * created */
    struct s2n_cipher_suite *cipher_suites_benchmark[] = {
        all_suites[state.range(1)]
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

    struct verify_data *unsafe_verify_data = (verify_data *) malloc(sizeof(verify_data));
    s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;

    GUARD_EXIT(s2n_config_set_status_request_type(config, type),
               "OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");

    GUARD_EXIT(s2n_config_set_verify_host_callback(config, unsafe_verify_host, unsafe_verify_data),
               "Error setting host name verification function\n");

    unsafe_verify_data->trusted_host = host;

    if (!conn_settings.insecure) {
        const char *ca_dir = NULL;
        if(all_suites[state.range(0)]->auth_method == S2N_AUTHENTICATION_RSA) {
            std::string ca_file = "rsa_2048_sha384_client_cert.pem";
            std::string pem_file_location = pem_dir + ca_file;
            GUARD_EXIT(s2n_config_set_verification_ca_location(config, pem_file_location.c_str(), ca_dir),
                       "Error setting CA file for RSA trust store\n");
        }
        else {
            std::string ca_file = "ecdsa_p256_pkcs1_cert.pem";
            std::string pem_file_location = pem_dir + ca_file;
            GUARD_EXIT(s2n_config_set_verification_ca_location(config, pem_file_location.c_str(), ca_dir),
                       "Error setting CA file for ECDSA trust store\n");
        }
    }
    else {
        GUARD_EXIT(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
    }

    if (conn == NULL) {
        print_s2n_error("Error getting new connection");
        exit(1);
    }

    GUARD_EXIT(s2n_connection_set_config(conn, config), "Error setting configuration");

    GUARD_EXIT(s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL),
               "Error setting ClientAuth optional");

    if (conn_settings.use_corked_io) {
        GUARD_EXIT(s2n_connection_use_corked_io(conn), "Error setting corked io");
    }

    GUARD_EXIT(s2n_set_server_name(conn, host), "Error setting server name");
    GUARD_EXIT(s2n_connection_set_fd(conn, sockfd), "Error setting file descriptor");

    if (benchmark_negotiate(conn, sockfd, state, true) != S2N_SUCCESS) {
        state.SkipWithError("Negotiate Failed\n");
        if (DEBUG_PRINT) {
            printf("Error in negotiate!\n");
        }
    }

    if (DEBUG_PRINT) {
        printf("Connected to %s:%s\n", host, port);
    }

    for (size_t i = 0; i < warmup_iters; i++) {
        send_data(conn, state, true);
    }
    for (auto _ : state) {
        state.PauseTiming();
        send_data(conn, state, false);
    }

    s2n_blocked_status blocked;
    int shutdown_rc = s2n_shutdown(conn, &blocked);
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    free(unsafe_verify_data);
    GUARD_EXIT(s2n_connection_wipe(conn), "Error wiping connection");
    GUARD_EXIT(s2n_config_free(config), "Error freeing configuration");
    GUARD_EXIT(s2n_connection_free(conn), "Error freeing connection");
}

int start_benchmark_send_client(int argc, char** argv) {
    int use_corked_io = 0;
    int insecure = 1;
    conn_settings = {0};
    char bench_format[100] = "--benchmark_out_format=";
    char bench_out[100] = "--benchmark_out=client_";
    std::string file_prefix;
    std::string gb_options;
    std::vector<int> data_sizes;
    long int warmup_iters = 1;
    size_t iterations = 1;
    size_t repetitions = 1;
    int sockfd = 0;

    argument_parse(argc, argv, use_corked_io, insecure, bench_format, file_prefix, warmup_iters, iterations, repetitions,
                   gb_options, data_sizes);

    if(data_sizes.size() == 0) {
        data_sizes = { 1, 100, 1000, 10000, 100000, 1000000 };
    }

    strcat(bench_out, file_prefix.c_str());
    std::vector<char*> argv_bench(argv, argv + argc);
    argv_bench.push_back(bench_out);
    argv_bench.push_back(bench_format);


    argv_bench.push_back(nullptr);
    argv = argv_bench.data();
    argc = argv_bench.size();

    conn_settings.use_corked_io = use_corked_io;
    conn_settings.insecure = insecure;

    s2n_init();

    GUARD_EXIT(setup_socket(sockfd), "Server socket setup failed");
    for(long int current_suite = 0; current_suite < num_suites; current_suite++) {
        std::string bench_name = std::string("Client: ") + all_suites[current_suite]->name;

        for (int current_data_index = 0; current_data_index < (int)data_sizes.size(); current_data_index++) {
            benchmark::RegisterBenchmark(bench_name.c_str(), benchmark_send_single_suite_client)
                ->ReportAggregatesOnly()
                ->Repetitions(repetitions)
                ->Iterations(iterations)
                ->Args({ data_sizes[current_data_index], current_suite, warmup_iters, sockfd });
        }
    }
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();

    s2n_cleanup();
    close(sockfd);
    return 0;
}
