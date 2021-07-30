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
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int pid_server = fork();
    if(pid_server == 0) {
        int result = system("~/s2n-tls/build/bin/s2n_neg_server_benchmark");
        printf("%d\n", result);
    }
    else {
        int result = system("~/s2n-tls/build/bin/s2n_neg_client_benchmark");
        printf("%d\n", result);

    }
    return 0;
}



