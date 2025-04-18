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

#include "tls/s2n_tls13_certificate_verify.h"

#include <stdint.h>

#include "crypto/s2n_hash.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_async_pkey.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

/**
  * Specified in https://tools.ietf.org/html/rfc8446#section-4.4.3
  *
  * Servers MUST send this message when authenticating via a certificate.  
  * Clients MUST send this message whenever authenticating via a certificate. 
  * When sent, this message MUST appear immediately after the Certificate 
  * message and immediately prior to the Finished message.
 **/

/* 64 'space' characters (0x20) */
const uint8_t S2N_CERT_VERIFY_PREFIX[] = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
/* 'TLS 1.3, server CertificateVerify' with 0x00 separator */
const uint8_t S2N_SERVER_CERT_VERIFY_CONTEXT[] = { 0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33,
    0x2c, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
    0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00 };
/* 'TLS 1.3, client CertificateVerify' with 0x00 separator */
const uint8_t S2N_CLIENT_CERT_VERIFY_CONTEXT[] = { 0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33,
    0x2c, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
    0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00 };

#define S2N_CERT_VERIFY_MAX_CONTEXT_SIZE \
    (MAX(sizeof(S2N_SERVER_CERT_VERIFY_CONTEXT), sizeof(S2N_CLIENT_CERT_VERIFY_CONTEXT))
#define S2N_CERT_VERIFY_MAX_DATA_SIZE \
    (sizeof(S2N_CERT_VERIFY_PREFIX) + S2N_MAX_DIGEST_LEN + S2N_CERT_VERIFY_MAX_CONTEXT_SIZE))

static int s2n_tls13_write_cert_verify_signature(struct s2n_connection *conn,
        const struct s2n_signature_scheme *chosen_sig_scheme);
static int s2n_tls13_write_signature(struct s2n_connection *conn, struct s2n_blob *signature);
int s2n_tls13_generate_unsigned_cert_verify_content(struct s2n_connection *conn,
        struct s2n_hash_state *signing_input, s2n_mode mode);
static int s2n_tls13_cert_read_and_verify_signature(struct s2n_connection *conn,
        const struct s2n_signature_scheme *chosen_sig_scheme);

int s2n_tls13_cert_verify_send(struct s2n_connection *conn)
{
    S2N_ASYNC_PKEY_GUARD(conn);

    if (conn->mode == S2N_SERVER) {
        /* Write digital signature */
        POSIX_GUARD(s2n_tls13_write_cert_verify_signature(conn, conn->handshake_params.server_cert_sig_scheme));
    } else {
        /* Write digital signature */
        POSIX_GUARD(s2n_tls13_write_cert_verify_signature(conn, conn->handshake_params.client_cert_sig_scheme));
    }

    return 0;
}

static S2N_RESULT s2n_pkey_signing_input(struct s2n_hash_state *hash_state,
        s2n_hash_algorithm hash_alg, struct s2n_blob *buffer)
{
    if (hash_alg == S2N_HASH_INTRINSIC) {
        RESULT_GUARD(s2n_hash_new_raw(hash_state, buffer));
    } else {
        RESULT_GUARD_POSIX(s2n_hash_new(hash_state));
    }
    RESULT_GUARD_POSIX(s2n_hash_init(hash_state, hash_alg));
    return S2N_RESULT_OK;
}

int s2n_tls13_write_cert_verify_signature(struct s2n_connection *conn,
        const struct s2n_signature_scheme *chosen_sig_scheme)
{
    POSIX_ENSURE_REF(conn->handshake_params.our_chain_and_key);

    /* Write the SignatureScheme out */
    struct s2n_stuffer *out = &conn->handshake.io;
    POSIX_GUARD(s2n_stuffer_write_uint16(out, chosen_sig_scheme->iana_value));

    uint8_t buffer_data[S2N_CERT_VERIFY_MAX_DATA_SIZE] = { 0 };
    struct s2n_blob buffer = { 0 };
    DEFER_CLEANUP(struct s2n_hash_state signing_input = { 0 }, s2n_hash_free);
    POSIX_GUARD(s2n_blob_init(&buffer, buffer_data, sizeof(buffer_data)));
    POSIX_GUARD_RESULT(s2n_pkey_signing_input(&signing_input,
            chosen_sig_scheme->hash_alg, &buffer));

    POSIX_GUARD(s2n_tls13_generate_unsigned_cert_verify_content(conn, &signing_input, conn->mode));

    S2N_ASYNC_PKEY_SIGN(conn, chosen_sig_scheme->sig_alg, &signing_input, s2n_tls13_write_signature);
}

int s2n_tls13_write_signature(struct s2n_connection *conn, struct s2n_blob *signature)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    POSIX_GUARD(s2n_stuffer_write_uint16(out, signature->size));
    POSIX_GUARD(s2n_stuffer_write_bytes(out, signature->data, signature->size));

    return 0;
}

int s2n_tls13_generate_unsigned_cert_verify_content(struct s2n_connection *conn,
        struct s2n_hash_state *signing_input, s2n_mode mode)
{
    s2n_tls13_connection_keys(tls13_ctx, conn);

    uint8_t hash_digest_length = tls13_ctx.size;
    uint8_t digest_out[S2N_MAX_DIGEST_LEN] = { 0 };

    /* Get current handshake transcript digest */
    POSIX_ENSURE_REF(conn->handshake.hashes);
    struct s2n_hash_state *hash_state = &conn->handshake.hashes->hash_workspace;
    POSIX_GUARD_RESULT(s2n_handshake_copy_hash_state(conn, tls13_ctx.hash_algorithm, hash_state));
    POSIX_GUARD(s2n_hash_digest(hash_state, digest_out, hash_digest_length));

    /* Write the content to be signed/verified */
    POSIX_GUARD(s2n_hash_update(signing_input, S2N_CERT_VERIFY_PREFIX, sizeof(S2N_CERT_VERIFY_PREFIX)));
    if (mode == S2N_CLIENT) {
        POSIX_GUARD(s2n_hash_update(signing_input, S2N_CLIENT_CERT_VERIFY_CONTEXT,
                sizeof(S2N_CLIENT_CERT_VERIFY_CONTEXT)));
    } else {
        POSIX_GUARD(s2n_hash_update(signing_input, S2N_SERVER_CERT_VERIFY_CONTEXT,
                sizeof(S2N_SERVER_CERT_VERIFY_CONTEXT)));
    }
    POSIX_GUARD(s2n_hash_update(signing_input, digest_out, hash_digest_length));

    return S2N_SUCCESS;
}

int s2n_tls13_cert_verify_recv(struct s2n_connection *conn)
{
    POSIX_GUARD_RESULT(s2n_signature_algorithm_recv(conn, &conn->handshake.io));
    /* Read the rest of the signature and verify */
    if (conn->mode == S2N_SERVER) {
        POSIX_GUARD(s2n_tls13_cert_read_and_verify_signature(conn,
                conn->handshake_params.client_cert_sig_scheme));
    } else {
        POSIX_GUARD(s2n_tls13_cert_read_and_verify_signature(conn,
                conn->handshake_params.server_cert_sig_scheme));
    }

    return 0;
}

int s2n_tls13_cert_read_and_verify_signature(struct s2n_connection *conn,
        const struct s2n_signature_scheme *chosen_sig_scheme)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get signature size */
    uint16_t signature_size = 0;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &signature_size));
    S2N_ERROR_IF(signature_size > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Get wire signature */
    struct s2n_blob signed_content = { 0 };
    uint8_t *signature_data = s2n_stuffer_raw_read(in, signature_size);
    POSIX_ENSURE_REF(signature_data);
    POSIX_GUARD(s2n_blob_init(&signed_content, signature_data, signature_size));

    uint8_t buffer_data[S2N_CERT_VERIFY_MAX_DATA_SIZE] = { 0 };
    struct s2n_blob buffer = { 0 };
    DEFER_CLEANUP(struct s2n_hash_state signing_input = { 0 }, s2n_hash_free);
    POSIX_GUARD(s2n_blob_init(&buffer, buffer_data, sizeof(buffer_data)));
    POSIX_GUARD_RESULT(s2n_pkey_signing_input(&signing_input,
            chosen_sig_scheme->hash_alg, &buffer));

    /* We generate cert verify content for the peer's mode, not our own,
     * because we are verifying the peer's signature rather than signing. */
    POSIX_GUARD(s2n_tls13_generate_unsigned_cert_verify_content(conn, &signing_input, S2N_PEER_MODE(conn->mode)));

    const struct s2n_pkey *pkey = (conn->mode == S2N_CLIENT) ?
            &conn->handshake_params.server_public_key :
            &conn->handshake_params.client_public_key;

    POSIX_GUARD(s2n_pkey_verify(pkey, chosen_sig_scheme->sig_alg, &signing_input, &signed_content));
    return S2N_SUCCESS;
}
