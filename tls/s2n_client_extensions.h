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

#include <stdint.h>
#include <string.h>

#include "crypto/s2n_signature.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"

extern int s2n_choose_preferred_signature_hash_pair(struct s2n_stuffer *in, int num_pairs, s2n_hash_algorithm *hash_alg, s2n_signature_algorithm *signature_alg);
extern int s2n_recv_client_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *in, s2n_hash_algorithm *out, s2n_signature_algorithm *signature_alg);
extern int s2n_send_client_signature_algorithms(struct s2n_stuffer *out);
