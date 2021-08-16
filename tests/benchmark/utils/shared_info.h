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



#include <s2n.h>
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_cipher_preferences.h"
#include <benchmark/benchmark.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <string>
#include <vector>
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
#include <netinet/tcp.h>
#include <iostream>
#include <sys/stat.h>
#include <sys/mman.h>
#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"




extern struct s2n_cipher_suite **all_suites;
extern unsigned int num_suites;

extern char bench_format[100];
extern char file_prefix[100];

extern uint8_t ticket_key_name[16];

extern uint8_t default_ticket_key[32];

extern int DEBUG_PRINT;
extern int WARMUP_ITERS;
extern unsigned int ITERATIONS;
extern int use_corked_io;
extern const char *host;
extern const char *port;
extern uint8_t insecure;

int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state, bool warmup);
void argument_parse(int argc, char** argv);