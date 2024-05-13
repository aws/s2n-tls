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

#pragma once

#include <stdint.h>

#include "api/s2n.h"

#define GUARD_EXIT_NULL(x)                                 \
    do {                                                   \
        if (x == NULL) {                                   \
            fprintf(stderr, "NULL pointer encountered\n"); \
            exit(1);                                       \
        }                                                  \
    } while (0)

#define GUARD_EXIT(x, msg)        \
    do {                          \
        if ((x) < 0) {            \
            print_s2n_error(msg); \
            exit(1);              \
        }                         \
    } while (0)

#define ENSURE_EXIT(x, msg)               \
    do {                                  \
        if (!(x)) {                       \
            fprintf(stderr, "%s\n", msg); \
            exit(1);                      \
        }                                 \
    } while (0)

#define GUARD_RETURN_NULL(x)                               \
    do {                                                   \
        if (x == NULL) {                                   \
            fprintf(stderr, "NULL pointer encountered\n"); \
            return -1;                                     \
        }                                                  \
    } while (0)

#define GUARD_RETURN(x, msg)      \
    do {                          \
        if ((x) < 0) {            \
            print_s2n_error(msg); \
            return -1;            \
        }                         \
    } while (0)

#define ENSURE_RETURN(x, msg)             \
    do {                                  \
        if (!(x)) {                       \
            fprintf(stderr, "%s\n", msg); \
            return -1;                    \
        }                                 \
    } while (0)

#define S2N_MAX_PSK_LIST_LENGTH 10
#define MAX_KEY_LEN             32
#define MAX_VAL_LEN             255

struct session_cache_entry {
    uint8_t key[MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t value[MAX_VAL_LEN];
    uint8_t value_len;
};

struct verify_data {
    const char *trusted_host;
};

struct conn_settings {
    unsigned mutual_auth : 1;
    unsigned self_service_blinding : 1;
    unsigned only_negotiate : 1;
    unsigned prefer_throughput : 1;
    unsigned prefer_low_latency : 1;
    unsigned enable_mfl : 1;
    unsigned session_ticket : 1;
    unsigned session_cache : 1;
    unsigned insecure : 1;
    unsigned use_corked_io : 1;
    unsigned https_server : 1;
    uint32_t https_bench;
    int max_conns;
    const char *ca_dir;
    const char *ca_file;
    const char *serialize_out;
    const char *deserialize_in;
    char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
    size_t psk_list_len;
};

void print_s2n_error(const char *app_error);
void send_data(struct s2n_connection *conn, int sockfd, const char *data, uint64_t len, s2n_blocked_status *blocked);
int echo(struct s2n_connection *conn, int sockfd, bool *stop_echo);
int wait_for_event(int fd, s2n_blocked_status blocked);
int negotiate(struct s2n_connection *conn, int sockfd);
int renegotiate(struct s2n_connection *conn, int sockfd, bool wait);
int wait_for_shutdown(struct s2n_connection *conn, int sockfd);
int early_data_recv(struct s2n_connection *conn);
int early_data_send(struct s2n_connection *conn, uint8_t *data, uint32_t len);
int print_connection_info(struct s2n_connection *conn);
int https(struct s2n_connection *conn, uint32_t bench);
int key_log_callback(void *ctx, struct s2n_connection *conn, uint8_t *logline, size_t len);

int cache_store_callback(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size);
int cache_retrieve_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value, uint64_t *value_size);
int cache_delete_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size);

/**
 * Writes array data to the the file specified
 *
 * @param path Path to the file where this data will be written
 * @param data The data to be outputted
 * @param length Length of the `data` array
 */
int write_array_to_file(const char *path, uint8_t *data, size_t length);

/**
 * Gets size of file
 *
 * @param path Path to the file
 * @param length A pointer which will be set to the size of the file
 */
int get_file_size(const char *path, size_t *length);

/**
 * Reads in data from file into a C array
 *
 *  * # Safety
 *
 * `data` must have at least `max_length` of memory available
 *
 * @param path Path to the file
 * @param data A pointer which will be set to the data in the file
 * @param max_length The maximum amount of data that can be written to the `data` pointer
 */
int load_file_to_array(const char *path, uint8_t *data, size_t max_length);
char *load_file_to_cstring(const char *path);
int s2n_str_hex_to_bytes(const unsigned char *hex, uint8_t *out_bytes, uint32_t max_out_bytes_len);
int s2n_setup_external_psk_list(struct s2n_connection *conn, char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH], size_t psk_list_len);
uint8_t unsafe_verify_host(const char *host_name, size_t host_name_len, void *data);
int s2n_setup_server_connection(struct s2n_connection *conn, int fd, struct s2n_config *config, struct conn_settings settings);
int s2n_set_common_server_config(int max_early_data, struct s2n_config *config, struct conn_settings conn_settings, const char *cipher_prefs, const char *session_ticket_key_file_path);
int s2n_connection_serialize_out(struct s2n_connection *conn, const char *file_path);
int s2n_connection_deserialize_in(struct s2n_connection *conn, const char *file_path);
