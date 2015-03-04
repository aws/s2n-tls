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

#include "crypto/s2n_rsa.h"
#include "crypto/s2n_dhe.h"

#include "utils/s2n_blob.h"
#include "api/s2n.h"

#define S2N_MAX_SERVER_NAME 256

struct s2n_cert_chain {
    struct s2n_blob cert;
    struct s2n_cert_chain *next;
};

struct s2n_cert_chain_and_key {
    uint32_t chain_size;
    struct s2n_cert_chain *head;
    struct s2n_rsa_private_key private_key;
    struct s2n_blob ocsp_status;
    char server_name[S2N_MAX_SERVER_NAME];
};

struct s2n_config {
    struct s2n_dh_params *dhparams;
    struct s2n_cert_chain_and_key *cert_and_key_pairs;
    struct s2n_cipher_preferences *cipher_preferences;
    struct s2n_blob application_protocols;
    s2n_status_request_type status_request_type;
};

extern struct s2n_config s2n_default_config;
