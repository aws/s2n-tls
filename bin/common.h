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
/* Remove once the PSK feature is released */
#include "tls/s2n_psk.h"

#define GUARD_EXIT_NULL(x)                                 \
    do {                                                   \
        if (x == NULL) {                                   \
            fprintf(stderr, "NULL pointer encountered\n"); \
            exit(1);                                       \
        }                                                  \
    } while (0)

#define GUARD_EXIT(x, msg)  \
  do {                      \
    if ((x) < 0) {          \
      print_s2n_error(msg); \
      exit(1);              \
    }                       \
  } while (0)

#define GUARD_RETURN(x, msg) \
  do {                       \
    if ((x) < 0) {           \
      print_s2n_error(msg);  \
      return -1;             \
    }                        \
  } while (0)

#define S2N_MAX_PSK_LIST_LENGTH 10

void print_s2n_error(const char *app_error);
int echo(struct s2n_connection *conn, int sockfd);
int negotiate(struct s2n_connection *conn, int sockfd);
int https(struct s2n_connection *conn, uint32_t bench);
int key_log_callback(void *ctx, struct s2n_connection *conn, uint8_t *logline, size_t len);

char *load_file_to_cstring(const char *path);
int s2n_str_hex_to_bytes(const unsigned char *hex, uint8_t *out_bytes, uint32_t max_out_bytes_len);
int s2n_setup_external_psk_list(struct s2n_connection *conn, char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH], size_t psk_list_len);
