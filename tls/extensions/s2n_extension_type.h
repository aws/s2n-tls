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

#include "stuffer/s2n_stuffer.h"

typedef uint8_t s2n_extension_type_id;
extern const s2n_extension_type_id s2n_unsupported_extension;

typedef struct {
    uint16_t iana_value;
    unsigned is_response:1;

    int (*send) (struct s2n_connection *conn, struct s2n_stuffer *out);
    int (*recv) (struct s2n_connection *conn, struct s2n_stuffer *in);

    int (*should_send) (struct s2n_connection *conn);
    int (*should_recv) (struct s2n_connection *conn, uint8_t *is_required);
} s2n_extension_type;

int s2n_extension_send(s2n_extension_type *extension_type, struct s2n_connection *conn, struct s2n_stuffer *out);
int s2n_extension_recv(s2n_extension_type *extension_type, struct s2n_connection *conn, struct s2n_stuffer *in);

/* Initializer */
int s2n_extension_type_init();

/* Convert the IANA value (which ranges from 0->65535) to an id with a more
 * constrained range. That id can be used for bitfields, array indexes, etc.
 * to avoid allocating too much memory. */
s2n_extension_type_id s2n_extension_iana_value_to_id(uint16_t iana_value);

/* Common implementations for send */
int s2n_extension_send_unimplemented(struct s2n_connection *conn, struct s2n_stuffer *out);

/* Common implementations for recv */
int s2n_extension_recv_unimplemented(struct s2n_connection *conn, struct s2n_stuffer *in);

/* Common implementations for should_send */
int s2n_extension_always_send(struct s2n_connection *conn);
int s2n_extension_never_send(struct s2n_connection *conn);

/* Common implementations for should_recv */
int s2n_extension_always_recv(struct s2n_connection *conn, uint8_t *is_required);
int s2n_extension_may_recv(struct s2n_connection *conn, uint8_t *is_required);
