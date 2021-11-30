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

#include "api/s2n.h"
#include <benchmark/benchmark.h>
#include <netdb.h>
#include <getopt.h>
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_cipher_preferences.h"

extern struct s2n_cipher_suite **all_suites;
extern unsigned int num_suites;
extern int DEBUG_PRINT;
extern const char *host;
extern const char *port;
extern const char *pem_dir;
extern struct s2n_config *config;
extern struct conn_settings conn_settings;

extern const char *rsa_certificate_chain;
extern const char *rsa_private_key;
extern const char *ecdsa_certificate_chain;
extern const char *ecdsa_private_key;

int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state, bool warmup);
void argument_parse(int argc, char** argv, int& use_corked_io, int& insecure, char* bench_format,
                    std::string& file_prefix, long int& warmup_iters, size_t& iterations, size_t& repetitions,
                    std::string& gb_options, std::vector<int> &data_sizes);
