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

#include <unistd.h>
#include <stdio.h>
#include "s2n_neg_client_benchmark.h"
#include "s2n_neg_server_benchmark.h"

int main(int argc, char** argv) {
    int pid_server = fork();
    if(pid_server == 0) {
        Server s;
        s.start_benchmark_server(argc, argv);
    }
    else {
        unsigned int microsecond = 1000000;
        usleep(0.1 * microsecond);
        Client c;
        c.start_benchmark_client(argc, argv);
    }
    return 0;
}



