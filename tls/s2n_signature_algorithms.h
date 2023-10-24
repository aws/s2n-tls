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

#include "api/s2n.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_signature_scheme.h"

struct s2n_connection;

struct s2n_sig_scheme_list {
    uint16_t iana_list[TLS_SIGNATURE_SCHEME_LIST_MAX_LEN];
    uint8_t len;
};

int s2n_choose_default_sig_scheme(struct s2n_connection *conn,
        const struct s2n_signature_scheme **sig_scheme_out, s2n_mode signer);
int s2n_tls13_default_sig_scheme(struct s2n_connection *conn,
        const struct s2n_signature_scheme **sig_scheme_out);

int s2n_choose_sig_scheme_from_peer_preference_list(struct s2n_connection *conn,
        struct s2n_sig_scheme_list *sig_hash_algs,
        const struct s2n_signature_scheme **sig_scheme_out);
int s2n_get_and_validate_negotiated_signature_scheme(struct s2n_connection *conn, struct s2n_stuffer *in,
        const struct s2n_signature_scheme **chosen_sig_scheme);

int s2n_recv_supported_sig_scheme_list(struct s2n_stuffer *in, struct s2n_sig_scheme_list *sig_hash_algs);
S2N_RESULT s2n_signature_algorithms_supported_list_send(struct s2n_connection *conn,
        struct s2n_stuffer *out);
