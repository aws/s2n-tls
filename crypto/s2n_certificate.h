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

#include "crypto/s2n_rsa.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_config.h"

struct s2n_cert_public_key {
    s2n_cert_type cert_type;
    union {
        struct s2n_rsa_public_key rsa;
        /* TODO: Support other Public Key Types (Eg ECDSA) */
    } public_key;
};

int s2n_send_cert_chain(struct s2n_stuffer *out, struct s2n_cert_chain_and_key *chain);
