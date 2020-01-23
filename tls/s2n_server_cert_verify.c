/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_certificate_verify.h"
#include "tls/s2n_connection.h"
#include "crypto/s2n_hash.h"

#include "stuffer/s2n_stuffer.h"
#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

static int s2n_server_write_cert_verify_signature(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_server_generate_unsigned_cert_verify_content(struct s2n_connection *conn, struct s2n_stuffer *unsigned_content);
static uint8_t s2n_server_cert_verify_header_length();

int s2n_server_cert_verify_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Write the SignatureScheme out */
    GUARD(s2n_stuffer_write_uint16(out, conn->secure.conn_sig_scheme.iana_value));

    /* Write digital signature */
    GUARD(s2n_server_write_cert_verify_signature(conn, out));

    return 0;
}

int s2n_server_cert_read_and_verify_signature(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    DEFER_CLEANUP(struct s2n_blob signed_content = {0}, s2n_free);
    DEFER_CLEANUP(struct s2n_stuffer unsigned_content = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_hash_state message_hash = {0}, s2n_hash_free);
    GUARD(s2n_hash_new(&message_hash));

    struct s2n_signature_scheme chosen_sig_scheme = conn->secure.conn_sig_scheme;

    /* Get signature size */
    uint16_t signature_size;
    GUARD(s2n_stuffer_read_uint16(in, &signature_size));
    S2N_ERROR_IF(signature_size > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Get wire signature */
    GUARD(s2n_alloc(&signed_content, signature_size));
    signed_content.size = signature_size;
    GUARD(s2n_stuffer_read_bytes(in, signed_content.data, signature_size));

    /* Verify signature */
    GUARD(s2n_server_generate_unsigned_cert_verify_content(conn, &unsigned_content));

    GUARD(s2n_hash_init(&message_hash, chosen_sig_scheme.hash_alg));
    GUARD(s2n_hash_update(&message_hash, unsigned_content.blob.data, s2n_stuffer_data_available(&unsigned_content)));
    GUARD(s2n_pkey_verify(&conn->secure.server_public_key, &message_hash, &signed_content));

    return 0;
}


int s2n_server_cert_verify_recv(struct s2n_connection *conn)
{
    /* Read the algorithm and update conn->secure.conn_sig_scheme */
    GUARD(s2n_get_and_validate_negotiated_signature_scheme(conn, &conn->handshake.io, &conn->secure.conn_sig_scheme));
    /* Read the rest of the signature and verify */
    GUARD(s2n_server_cert_read_and_verify_signature(conn));

    return 0;
}

int s2n_server_write_cert_verify_signature(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn->handshake_params.our_chain_and_key);
    const struct s2n_pkey *pkey = conn->handshake_params.our_chain_and_key->private_key;

    DEFER_CLEANUP(struct s2n_blob signed_content = {0}, s2n_free);
    DEFER_CLEANUP(struct s2n_hash_state message_hash = {0}, s2n_hash_free);
    DEFER_CLEANUP(struct s2n_stuffer unsigned_content = {0}, s2n_stuffer_free);
    GUARD(s2n_hash_new(&message_hash));
    GUARD(s2n_hash_init(&message_hash, conn->secure.conn_sig_scheme.hash_alg));

    uint32_t maximum_signature_length = s2n_pkey_size(pkey);
    GUARD(s2n_alloc(&signed_content, maximum_signature_length));
    signed_content.size = maximum_signature_length;

    GUARD(s2n_server_generate_unsigned_cert_verify_content(conn, &unsigned_content));

    GUARD(s2n_hash_update(&message_hash, unsigned_content.blob.data, s2n_stuffer_data_available(&unsigned_content)));
    GUARD(s2n_pkey_sign(pkey, &message_hash, &signed_content));

    GUARD(s2n_stuffer_write_uint16(out, signed_content.size));
    GUARD(s2n_stuffer_write_bytes(out, signed_content.data, signed_content.size));

    return 0;
}

/* Concatenates the handshake hash used for generating a Certificate Verify Signature. */
int s2n_server_generate_unsigned_cert_verify_content(struct s2n_connection *conn, struct s2n_stuffer *unsigned_content)
{
    s2n_tls13_connection_keys(tls13_ctx, conn);

    struct s2n_hash_state handshake_hash, hash_copy;
    uint8_t hash_digest_length = tls13_ctx.size;
    uint8_t digest_out[S2N_MAX_DIGEST_LEN];

    /* Get current handshake hash */
    GUARD(s2n_handshake_get_hash_state(conn, tls13_ctx.hash_algorithm, &handshake_hash));

    /* Copy current hash content */
    GUARD(s2n_hash_new(&hash_copy));
    GUARD(s2n_hash_copy(&hash_copy, &handshake_hash));
    GUARD(s2n_hash_digest(&hash_copy, digest_out, hash_digest_length));
    GUARD(s2n_hash_free(&hash_copy));

    /* Concatenate the content to be signed/verified */
    GUARD(s2n_stuffer_alloc(unsigned_content, hash_digest_length + s2n_server_cert_verify_header_length()));
    GUARD(s2n_stuffer_write_bytes(unsigned_content, S2N_CERT_VERIFY_PREFIX, sizeof(S2N_CERT_VERIFY_PREFIX)));
    GUARD(s2n_stuffer_write_bytes(unsigned_content, S2N_SERVER_CERT_VERIFY_CONTEXT, sizeof(S2N_SERVER_CERT_VERIFY_CONTEXT)));
    GUARD(s2n_stuffer_write_bytes(unsigned_content, digest_out, hash_digest_length));

    return 0;
}

uint8_t s2n_server_cert_verify_header_length()
{
    return sizeof(S2N_CERT_VERIFY_PREFIX) + sizeof(S2N_SERVER_CERT_VERIFY_CONTEXT);
}
