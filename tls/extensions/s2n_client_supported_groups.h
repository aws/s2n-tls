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

extern int s2n_extensions_client_supported_groups_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_recv_client_supported_groups(struct s2n_connection *conn, struct s2n_stuffer *extension);
int s2n_parse_client_supported_groups_list(struct s2n_connection *conn, struct s2n_blob *iana_ids, const struct s2n_ecc_named_curve **supported_groups);
int s2n_choose_supported_group(struct s2n_connection *conn, const struct s2n_ecc_named_curve **group_options, struct s2n_ecc_evp_params *chosen_group);
