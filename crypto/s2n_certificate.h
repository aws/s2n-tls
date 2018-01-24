/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "crypto/s2n_pkey.h"
#include "stuffer/s2n_stuffer.h"

#define S2N_MAX_SERVER_NAME 256

struct s2n_cert {
    s2n_cert_type cert_type;
    s2n_cert_public_key public_key;
    struct s2n_blob raw;
    struct s2n_cert *next;
};

struct s2n_cert_chain {
    uint32_t chain_size;
    struct s2n_cert *head;
};

struct s2n_cert_chain_and_key {
    struct s2n_cert_chain cert_chain;
    s2n_cert_private_key private_key;
    struct s2n_blob ocsp_status;
    struct s2n_blob sct_list;
    char server_name[S2N_MAX_SERVER_NAME];
};

int s2n_send_cert_chain(struct s2n_stuffer *out, struct s2n_cert_chain *chain);
int s2n_send_empty_cert_chain(struct s2n_stuffer *out);
int s2n_cert_set_cert_type(struct s2n_cert *cert, s2n_cert_type cert_type);
int s2n_cert_public_key_set_rsa_from_openssl(s2n_cert_public_key *cert_pub_key, RSA *rsa);
