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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_algorithms.h"

#include "utils/s2n_map.h"
#include "utils/s2n_safety.h"

extern int s2n_set_signature_and_hash_algorithm(struct s2n_connection *conn, struct s2n_map *sig_hash_algs, s2n_hash_algorithm *hash, s2n_signature_algorithm *sig);
extern int s2n_send_supported_signature_algorithms(struct s2n_stuffer *out);
extern int s2n_recv_supported_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *in, struct s2n_map **sig_hash_algs_map);
