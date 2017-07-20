/*
 * Copyright 2017 Amazon.com = Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License = Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS = WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND = either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "tls/s2n_connection_evp_digests.h"

#include "utils/s2n_safety.h"

/* On s2n_connection_wipe, save all pointers to OpenSSL EVP digest structs in a temporary
 * s2n_connection_prf_handles struct to avoid re-allocation after zeroing the connection struct.
 * Do not store any additional hash/HMAC state as it is unnecessary and excessive copying would impact performance.
 */
int s2n_connection_save_prf_state(struct s2n_connection_prf_handles *prf_handles, struct s2n_connection *conn)
{
    /* Preserve only the handlers for TLS PRF p_hash pointers to avoid re-allocation */
    prf_handles->p_hash_s2n_hmac_inner = conn->prf_space.tls.p_hash.s2n_hmac.inner.digest.high_level;
    prf_handles->p_hash_s2n_hmac_inner_just_key = conn->prf_space.tls.p_hash.s2n_hmac.inner_just_key.digest.high_level;
    prf_handles->p_hash_s2n_hmac_outer = conn->prf_space.tls.p_hash.s2n_hmac.outer.digest.high_level;
    prf_handles->p_hash_evp_hmac = conn->prf_space.tls.p_hash.evp_hmac;

    return 0;
}

/* On s2n_connection_wipe, save all pointers to OpenSSL EVP digest structs in a temporary
 * s2n_connection_hash_handles struct to avoid re-allocation after zeroing the connection struct.
 * Do not store any additional hash state as it is unnecessary and excessive copying would impact performance.
 */
int s2n_connection_save_hash_state(struct s2n_connection_hash_handles *hash_handles, struct s2n_connection *conn)
{
    /* Preserve only the handlers for handshake hash state pointers to avoid re-allocation */
    hash_handles->md5 = conn->handshake.md5.digest.high_level;
    hash_handles->sha1 = conn->handshake.sha1.digest.high_level;
    hash_handles->sha224 = conn->handshake.sha224.digest.high_level;
    hash_handles->sha256 = conn->handshake.sha256.digest.high_level;
    hash_handles->sha384 = conn->handshake.sha384.digest.high_level;
    hash_handles->sha512 = conn->handshake.sha512.digest.high_level;
    hash_handles->md5_sha1 = conn->handshake.md5_sha1.digest.high_level;
    hash_handles->sslv3_md5_copy = conn->handshake.sslv3_md5_copy.digest.high_level;
    hash_handles->sslv3_sha1_copy = conn->handshake.sslv3_sha1_copy.digest.high_level;
    hash_handles->tls_hash_copy = conn->handshake.tls_hash_copy.digest.high_level;

    /* Preserve only the handlers for SSLv3 PRF hash state pointers to avoid re-allocation */
    hash_handles->prf_md5 = conn->prf_space.ssl3.md5.digest.high_level;
    hash_handles->prf_sha1 = conn->prf_space.ssl3.sha1.digest.high_level;

    /* Preserve only the handlers for initial signature hash state pointers to avoid re-allocation */
    hash_handles->initial_signature_hash = conn->initial.signature_hash.digest.high_level;

    /* Preserve only the handlers for secure signature hash state pointers to avoid re-allocation */
    hash_handles->secure_signature_hash = conn->secure.signature_hash.digest.high_level;

    return 0;
}

/* On s2n_connection_wipe, save all pointers to OpenSSL EVP digest structs in a temporary
 * s2n_connection_hmac_handles struct to avoid re-allocation after zeroing the connection struct.
 * Do not store any additional HMAC state as it is unnecessary and excessive copying would impact performance.
 */
int s2n_connection_save_hmac_state(struct s2n_connection_hmac_handles *hmac_handles, struct s2n_connection *conn)
{
    /* Preserve only the handlers for initial client mac hmac state pointers to avoid re-allocation */
    hmac_handles->initial_client_mac_inner = conn->initial.client_record_mac.inner.digest.high_level;
    hmac_handles->initial_client_mac_inner_just_key = conn->initial.client_record_mac.inner_just_key.digest.high_level;
    hmac_handles->initial_client_mac_outer = conn->initial.client_record_mac.outer.digest.high_level;

    /* Preserve only the handlers for initial server mac hmac state pointers to avoid re-allocation */
    hmac_handles->initial_server_mac_inner = conn->initial.server_record_mac.inner.digest.high_level;
    hmac_handles->initial_server_mac_inner_just_key = conn->initial.server_record_mac.inner_just_key.digest.high_level;
    hmac_handles->initial_server_mac_outer = conn->initial.server_record_mac.outer.digest.high_level;

    /* Preserve only the handlers for initial record mac copy hmac state pointers to avoid re-allocation */
    hmac_handles->initial_client_mac_copy_inner = conn->initial.record_mac_copy_workspace.inner.digest.high_level;
    hmac_handles->initial_client_mac_copy_inner_just_key = conn->initial.record_mac_copy_workspace.inner_just_key.digest.high_level;
    hmac_handles->initial_client_mac_copy_outer = conn->initial.record_mac_copy_workspace.outer.digest.high_level;

    /* Preserve only the handlers for secure client mac hmac state pointers to avoid re-allocation */
    hmac_handles->secure_client_mac_inner = conn->secure.client_record_mac.inner.digest.high_level;
    hmac_handles->secure_client_mac_inner_just_key = conn->secure.client_record_mac.inner_just_key.digest.high_level;
    hmac_handles->secure_client_mac_outer = conn->secure.client_record_mac.outer.digest.high_level;

    /* Preserve only the handlers for secure server mac hmac state pointers to avoid re-allocation */
    hmac_handles->secure_server_mac_inner = conn->secure.server_record_mac.inner.digest.high_level;
    hmac_handles->secure_server_mac_inner_just_key = conn->secure.server_record_mac.inner_just_key.digest.high_level;
    hmac_handles->secure_server_mac_outer = conn->secure.server_record_mac.outer.digest.high_level;

    /* Preserve only the handlers for secure record mac copy hmac state pointers to avoid re-allocation */
    hmac_handles->secure_client_mac_copy_inner = conn->secure.record_mac_copy_workspace.inner.digest.high_level;
    hmac_handles->secure_client_mac_copy_inner_just_key = conn->secure.record_mac_copy_workspace.inner_just_key.digest.high_level;
    hmac_handles->secure_client_mac_copy_outer = conn->secure.record_mac_copy_workspace.outer.digest.high_level;

    return 0;
}

/* On s2n_connection_wipe, restore all pointers to OpenSSL EVP digest structs after zeroing the connection struct
 * to avoid re-allocation. Do not store any additional hash/HMAC state as it is unnecessary and excessive copying
 * would impact performance.
 */
int s2n_connection_restore_prf_state(struct s2n_connection *conn, struct s2n_connection_prf_handles *prf_handles)
{
    /* Restore s2n_connection handlers for TLS PRF p_hash */
    conn->prf_space.tls.p_hash.s2n_hmac.inner.digest.high_level = prf_handles->p_hash_s2n_hmac_inner;
    conn->prf_space.tls.p_hash.s2n_hmac.inner_just_key.digest.high_level = prf_handles->p_hash_s2n_hmac_inner_just_key;
    conn->prf_space.tls.p_hash.s2n_hmac.outer.digest.high_level = prf_handles->p_hash_s2n_hmac_outer;
    conn->prf_space.tls.p_hash.evp_hmac = prf_handles->p_hash_evp_hmac;

    return 0;
}

/* On s2n_connection_wipe, restore all pointers to OpenSSL EVP digest structs after zeroing the connection struct
 * to avoid re-allocation. Do not store any additional hash state as it is unnecessary and excessive copying
 * would impact performance.
 */
int s2n_connection_restore_hash_state(struct s2n_connection *conn, struct s2n_connection_hash_handles *hash_handles)
{
    /* Restore s2n_connection handlers for handshake hash states */
    conn->handshake.md5.digest.high_level = hash_handles->md5;
    conn->handshake.sha1.digest.high_level = hash_handles->sha1;
    conn->handshake.sha224.digest.high_level = hash_handles->sha224;
    conn->handshake.sha256.digest.high_level = hash_handles->sha256;
    conn->handshake.sha384.digest.high_level = hash_handles->sha384;
    conn->handshake.sha512.digest.high_level = hash_handles->sha512;
    conn->handshake.md5_sha1.digest.high_level = hash_handles->md5_sha1;
    conn->handshake.sslv3_md5_copy.digest.high_level = hash_handles->sslv3_md5_copy;
    conn->handshake.sslv3_sha1_copy.digest.high_level = hash_handles->sslv3_sha1_copy;
    conn->handshake.tls_hash_copy.digest.high_level = hash_handles->tls_hash_copy;

    /* Restore s2n_connection handlers for SSLv3 PRF hash states */
    conn->prf_space.ssl3.md5.digest.high_level = hash_handles->prf_md5;
    conn->prf_space.ssl3.sha1.digest.high_level = hash_handles->prf_sha1;

    /* Restore s2n_connection handlers for initial signature hash states */
    conn->initial.signature_hash.digest.high_level = hash_handles->initial_signature_hash;

    /* Restore s2n_connection handlers for secure signature hash states */
    conn->secure.signature_hash.digest.high_level = hash_handles->secure_signature_hash;

    return 0;
}

/* On s2n_connection_wipe, restore all pointers to OpenSSL EVP digest structs after zeroing the connection struct
 * to avoid re-allocation. Do not store any additional HMAC state as it is unnecessary and excessive copying
 * would impact performance.
 */
int s2n_connection_restore_hmac_state(struct s2n_connection *conn, struct s2n_connection_hmac_handles *hmac_handles)
{
    /* Restore s2n_connection handlers for initial client record mac */
    conn->initial.client_record_mac.inner.digest.high_level = hmac_handles->initial_client_mac_inner;
    conn->initial.client_record_mac.inner_just_key.digest.high_level = hmac_handles->initial_client_mac_inner_just_key;
    conn->initial.client_record_mac.outer.digest.high_level = hmac_handles->initial_client_mac_outer;

    /* Restore s2n_connection handlers for initial server record mac */
    conn->initial.server_record_mac.inner.digest.high_level = hmac_handles->initial_server_mac_inner;
    conn->initial.server_record_mac.inner_just_key.digest.high_level = hmac_handles->initial_server_mac_inner_just_key;
    conn->initial.server_record_mac.outer.digest.high_level = hmac_handles->initial_server_mac_outer;

    /* Restore s2n_connection handlers for initial record mac copy */
    conn->initial.record_mac_copy_workspace.inner.digest.high_level = hmac_handles->initial_client_mac_copy_inner;
    conn->initial.record_mac_copy_workspace.inner_just_key.digest.high_level = hmac_handles->initial_client_mac_copy_inner_just_key;
    conn->initial.record_mac_copy_workspace.outer.digest.high_level = hmac_handles->initial_client_mac_copy_outer;

    /* Restore s2n_connection handlers for secure client record mac */
    conn->secure.client_record_mac.inner.digest.high_level = hmac_handles->secure_client_mac_inner;
    conn->secure.client_record_mac.inner_just_key.digest.high_level = hmac_handles->secure_client_mac_inner_just_key;
    conn->secure.client_record_mac.outer.digest.high_level = hmac_handles->secure_client_mac_outer;

    /* Restore s2n_connection handlers for secure server record mac */
    conn->secure.server_record_mac.inner.digest.high_level = hmac_handles->secure_server_mac_inner;
    conn->secure.server_record_mac.inner_just_key.digest.high_level = hmac_handles->secure_server_mac_inner_just_key;
    conn->secure.server_record_mac.outer.digest.high_level = hmac_handles->secure_server_mac_outer;

    /* Restore s2n_connection handlers for secure record mac copy */
    conn->secure.record_mac_copy_workspace.inner.digest.high_level = hmac_handles->secure_client_mac_copy_inner;
    conn->secure.record_mac_copy_workspace.inner_just_key.digest.high_level = hmac_handles->secure_client_mac_copy_inner_just_key;
    conn->secure.record_mac_copy_workspace.outer.digest.high_level = hmac_handles->secure_client_mac_copy_outer;

    return 0;
}
