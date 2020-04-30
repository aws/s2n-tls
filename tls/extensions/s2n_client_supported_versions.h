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

extern const s2n_extension_type s2n_client_supported_versions_extension;

/* Old-style extension functions -- remove after extensions refactor is complete */
extern int s2n_extensions_client_supported_versions_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);
extern int s2n_extensions_client_supported_versions_size(struct s2n_connection *conn);
extern int s2n_extensions_client_supported_versions_send(struct s2n_connection *conn, struct s2n_stuffer *out);
