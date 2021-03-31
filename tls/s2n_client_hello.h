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
#include <s2n.h>

#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_extension_list.h"

#include "utils/s2n_array.h"
/*
 * the 'data' pointers in the below blobs
 * point to data in the raw_message stuffer
 */
struct s2n_client_hello {
    struct s2n_stuffer raw_message;

    s2n_parsed_extensions_list extensions;
    struct s2n_blob cipher_suites;

    unsigned int callback_invoked:1;
    unsigned int callback_async_blocked:1;
    unsigned int callback_async_done:1;
};

int s2n_client_hello_free(struct s2n_client_hello *client_hello);

extern struct s2n_client_hello *s2n_connection_get_client_hello(struct s2n_connection *conn);

extern ssize_t s2n_client_hello_get_raw_message_length(struct s2n_client_hello *ch);
extern ssize_t s2n_client_hello_get_raw_message(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);

extern ssize_t s2n_client_hello_get_cipher_suites_length(struct s2n_client_hello *ch);
extern ssize_t s2n_client_hello_get_cipher_suites(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);

extern ssize_t s2n_client_hello_get_extensions_length(struct s2n_client_hello *ch);
extern ssize_t s2n_client_hello_get_extensions(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
