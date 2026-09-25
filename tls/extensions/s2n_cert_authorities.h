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

/* The only defined bound on the size of the certificate_authorities is the maximum
 * size of an extension, UINT16_MAX. However, the full extensions list is also
 * limited to UINT16_MAX, so all the extensions on a message combined cannot exceed
 * UINT16_MAX. Other extensions could therefore limit the maximum size of the
 * certificate_authorities extension.
 *
 * To keep the limit predictable and avoid surprise errors during negotiation,
 * set a reasonable fixed limit.
 */
#define S2N_CERT_AUTHORITIES_MAX_SIZE (20000)

extern const s2n_extension_type s2n_cert_authorities_extension;

struct s2n_cert_chain_and_key;

bool s2n_cert_authorities_supported_from_trust_store();
int s2n_cert_authorities_send(struct s2n_connection *conn, struct s2n_stuffer *out);

/* Returns true (via *match) if any certificate in chain_and_key is issued by,
 * or is itself, a CA advertised by the peer in the certificate_authorities
 * extension. If no CA names were received, *match is false. */
S2N_RESULT s2n_cert_authorities_chain_matches(struct s2n_connection *conn,
        struct s2n_cert_chain_and_key *chain_and_key, bool *match);

struct s2n_cert;

/* Returns true (via *skip) if the given certificate should be omitted from the
 * certificate chain the server sends, because the client already advertised it
 * in the certificate_authorities extension. The leaf certificate (is_leaf) is
 * never skipped. Only applies to a server that received the extension; in all
 * other cases *skip is false. */
S2N_RESULT s2n_cert_authorities_should_skip_cert(struct s2n_connection *conn,
        struct s2n_cert *cert, bool is_leaf, bool *skip);
