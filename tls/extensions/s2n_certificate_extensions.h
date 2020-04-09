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

#include "tls/s2n_connection.h"
#include "stuffer/s2n_stuffer.h"

/* Guards against errors and non uint16s, then increments size */
#define GUARD_UINT16_AND_INCREMENT( x, size ) do { \
    GUARD(x); \
    lte_check(x, 65535); \
    size += x; \
} while (0)

int s2n_certificate_extensions_parse(struct s2n_connection *conn, struct s2n_blob *extensions);
int s2n_certificate_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out, struct s2n_cert_chain_and_key *chain_and_key);
int s2n_certificate_total_extensions_size(struct s2n_connection *conn, struct s2n_cert_chain_and_key *chain_and_key);
int s2n_certificate_extensions_size(struct s2n_connection *conn, struct s2n_cert_chain_and_key *chain_and_key);
int s2n_certificate_extensions_send_empty(struct s2n_stuffer *out);
