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
    POSIX_GUARD(s2n_hmac_save_evp_hash_state(&prf_handles->p_hash_s2n_hmac, &conn->prf_space.tls.p_hash.s2n_hmac));
    prf_handles->p_hash_evp_hmac = conn->prf_space.tls.p_hash.evp_hmac;

    return 0;
}

/* On s2n_connection_wipe, save all pointers to OpenSSL EVP digest structs in a temporary
 * s2n_connection_hmac_handles struct to avoid re-allocation after zeroing the connection struct.
 * Do not store any additional HMAC state as it is unnecessary and excessive copying would impact performance.
 */
int s2n_connection_save_hmac_state(struct s2n_connection_hmac_handles *hmac_handles, struct s2n_connection *conn)
{
    POSIX_GUARD(s2n_hmac_save_evp_hash_state(&hmac_handles->initial_client, &conn->initial.client_record_mac));
    POSIX_GUARD(s2n_hmac_save_evp_hash_state(&hmac_handles->initial_server, &conn->initial.server_record_mac));
    POSIX_GUARD(s2n_hmac_save_evp_hash_state(&hmac_handles->secure_client, &conn->secure.client_record_mac));
    POSIX_GUARD(s2n_hmac_save_evp_hash_state(&hmac_handles->secure_server, &conn->secure.server_record_mac));
    return 0;
}

/* On s2n_connection_wipe, restore all pointers to OpenSSL EVP digest structs after zeroing the connection struct
 * to avoid re-allocation. Do not store any additional hash/HMAC state as it is unnecessary and excessive copying
 * would impact performance.
 */
int s2n_connection_restore_prf_state(struct s2n_connection *conn, struct s2n_connection_prf_handles *prf_handles)
{
    /* Restore s2n_connection handlers for TLS PRF p_hash */
    POSIX_GUARD(s2n_hmac_restore_evp_hash_state(&prf_handles->p_hash_s2n_hmac, &conn->prf_space.tls.p_hash.s2n_hmac));
    conn->prf_space.tls.p_hash.evp_hmac = prf_handles->p_hash_evp_hmac;

    return 0;
}

/* On s2n_connection_wipe, restore all pointers to OpenSSL EVP digest structs after zeroing the connection struct
 * to avoid re-allocation. Do not store any additional HMAC state as it is unnecessary and excessive copying
 * would impact performance.
 */
int s2n_connection_restore_hmac_state(struct s2n_connection *conn, struct s2n_connection_hmac_handles *hmac_handles)
{
    POSIX_GUARD(s2n_hmac_restore_evp_hash_state(&hmac_handles->initial_client, &conn->initial.client_record_mac));
    POSIX_GUARD(s2n_hmac_restore_evp_hash_state(&hmac_handles->initial_server, &conn->initial.server_record_mac));
    POSIX_GUARD(s2n_hmac_restore_evp_hash_state(&hmac_handles->secure_client, &conn->secure.client_record_mac));
    POSIX_GUARD(s2n_hmac_restore_evp_hash_state(&hmac_handles->secure_server, &conn->secure.server_record_mac));
    return 0;
}
