/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>

#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"

#include "stuffer/s2n_stuffer.h"

struct s2n_connection;

struct s2n_sig_scheme_list {
    uint16_t iana_list[TLS_SIGNATURE_SCHEME_LIST_MAX_LEN];
    uint8_t len;
};

extern int s2n_get_signature_scheme_pref_list(struct s2n_connection *conn, const struct s2n_signature_scheme* const** pref_list_out,
                                              size_t *list_len_out);

extern int s2n_choose_sig_scheme_from_peer_preference_list(struct s2n_connection *conn, struct s2n_sig_scheme_list *sig_hash_algs,
                                                            struct s2n_signature_scheme *sig_scheme_out);
extern int s2n_get_and_validate_negotiated_signature_scheme(struct s2n_connection *conn, struct s2n_stuffer *in,
                                                            struct s2n_signature_scheme *chosen_sig_scheme);
extern int s2n_send_supported_signature_algorithms(struct s2n_stuffer *out);
extern int s2n_recv_supported_sig_scheme_list(struct s2n_stuffer *in, struct s2n_sig_scheme_list *sig_hash_algs);
