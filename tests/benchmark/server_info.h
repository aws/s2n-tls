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

uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data);

struct conn_settings {
    unsigned mutual_auth: 1;
    unsigned self_service_blinding: 1;
    unsigned only_negotiate: 1;
    unsigned prefer_throughput: 1;
    unsigned prefer_low_latency: 1;
    unsigned enable_mfl: 1;
    unsigned session_ticket: 1;
    unsigned session_cache: 1;
    unsigned insecure: 1;
    unsigned use_corked_io: 1;
    unsigned https_server: 1;
    uint32_t https_bench;
    int max_conns;
    const char *ca_dir;
    const char *ca_file;
    char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
    size_t psk_list_len;
};
