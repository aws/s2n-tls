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

struct s2n_connection;
struct s2n_config;

typedef enum { S2N_RENEGOTIATE_REJECT, S2N_RENEGOTIATE_ACCEPT} s2n_renegotiate_response;
typedef int (*s2n_renegotiate_request_cb)(struct s2n_connection *conn, void *context, s2n_renegotiate_response *response);
int s2n_config_set_renegotiate_request_cb(struct s2n_config *config, s2n_renegotiate_request_cb cb, void *ctx);

int s2n_renegotiate_wipe(struct s2n_connection *conn);
