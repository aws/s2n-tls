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

#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_connection.h"

/* The only fixed bound on the size of the certificate_authorities is the maximum
 * size of an extension (UINT16_MAX), but we need to ensure enough space for other
 * extensions as well.
 *
 * To keep the limit predictable and avoid surprise errors during negotiation,
 * set a reasonable limit.
 */
#define S2N_CERT_AUTHORITIES_MAX_SIZE (10000)

extern const s2n_extension_type s2n_cert_authorities_extension;

bool s2n_cert_authorities_supported_from_trust_store();
int s2n_cert_authorities_send(struct s2n_connection *conn, struct s2n_stuffer *out);
