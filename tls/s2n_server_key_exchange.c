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

#include "api/s2n.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_fips.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_async_pkey.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_algorithms.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

static int s2n_server_key_send_write_signature(struct s2n_connection *conn, struct s2n_blob *signature);

int s2n_server_key_recv(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(conn->secure->cipher_suite);
    POSIX_ENSURE_REF(conn->secure->cipher_suite->key_exchange_alg);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    struct s2n_hash_state *signature_hash = &conn->handshake.hashes->hash_workspace;
    const struct s2n_kex *key_exchange = conn->secure->cipher_suite->key_exchange_alg;
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob data_to_verify = { 0 };

    /* Read the KEX data */
    struct s2n_kex_raw_server_data kex_data = { 0 };
    POSIX_GUARD_RESULT(s2n_kex_server_key_recv_read_data(key_exchange, conn, &data_to_verify, &kex_data));

    POSIX_GUARD_RESULT(s2n_signature_algorithm_recv(conn, in));
    const struct s2n_signature_scheme *active_sig_scheme = conn->handshake_params.server_cert_sig_scheme;
    POSIX_ENSURE_REF(active_sig_scheme);

    /* FIPS specifically allows MD5 for <TLS1.2 */
    if (s2n_is_in_fips_mode() && conn->actual_protocol_version < S2N_TLS12) {
        POSIX_GUARD(s2n_hash_allow_md5_for_fips(signature_hash));
    }

    POSIX_GUARD(s2n_hash_init(signature_hash, active_sig_scheme->hash_alg));
    POSIX_GUARD(s2n_hash_update(signature_hash, conn->handshake_params.client_random, S2N_TLS_RANDOM_DATA_LEN));
    POSIX_GUARD(s2n_hash_update(signature_hash, conn->handshake_params.server_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Add KEX specific data */
    POSIX_GUARD(s2n_hash_update(signature_hash, data_to_verify.data, data_to_verify.size));

    /* Verify the signature */
    uint16_t signature_length = 0;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &signature_length));

    struct s2n_blob signature = { 0 };
    POSIX_GUARD(s2n_blob_init(&signature, s2n_stuffer_raw_read(in, signature_length), signature_length));

    POSIX_ENSURE_REF(signature.data);
    POSIX_ENSURE_GT(signature_length, 0);

    S2N_ERROR_IF(s2n_pkey_verify(&conn->handshake_params.server_public_key, active_sig_scheme->sig_alg, signature_hash, &signature) < 0,
            S2N_ERR_BAD_MESSAGE);

    /* We don't need the key any more, so free it */
    POSIX_GUARD(s2n_pkey_free(&conn->handshake_params.server_public_key));

    /* Parse the KEX data into whatever form needed and save it to the connection object */
    POSIX_GUARD_RESULT(s2n_kex_server_key_recv_parse_data(key_exchange, conn, &kex_data));
    return 0;
}

int s2n_ecdhe_server_key_recv_read_data(struct s2n_connection *conn, struct s2n_blob *data_to_verify,
        struct s2n_kex_raw_server_data *raw_server_data)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    POSIX_GUARD(s2n_ecc_evp_read_params(in, data_to_verify, &raw_server_data->ecdhe_data));
    return 0;
}

int s2n_ecdhe_server_key_recv_parse_data(struct s2n_connection *conn, struct s2n_kex_raw_server_data *raw_server_data)
{
    POSIX_GUARD(s2n_ecc_evp_parse_params(conn, &raw_server_data->ecdhe_data, &conn->kex_params.server_ecc_evp_params));

    return 0;
}

int s2n_dhe_server_key_recv_read_data(struct s2n_connection *conn, struct s2n_blob *data_to_verify,
        struct s2n_kex_raw_server_data *raw_server_data)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_dhe_raw_server_points *dhe_data = &raw_server_data->dhe_data;

    uint16_t p_length = 0;
    uint16_t g_length = 0;
    uint16_t Ys_length = 0;

    /* Keep a copy to the start of the whole structure for the signature check */
    data_to_verify->data = s2n_stuffer_raw_read(in, 0);
    POSIX_ENSURE_REF(data_to_verify->data);

    /* Read each of the three elements in */
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &p_length));
    dhe_data->p.size = p_length;
    dhe_data->p.data = s2n_stuffer_raw_read(in, p_length);
    POSIX_ENSURE_REF(dhe_data->p.data);

    POSIX_GUARD(s2n_stuffer_read_uint16(in, &g_length));
    dhe_data->g.size = g_length;
    dhe_data->g.data = s2n_stuffer_raw_read(in, g_length);
    POSIX_ENSURE_REF(dhe_data->g.data);

    POSIX_GUARD(s2n_stuffer_read_uint16(in, &Ys_length));
    dhe_data->Ys.size = Ys_length;
    dhe_data->Ys.data = s2n_stuffer_raw_read(in, Ys_length);
    POSIX_ENSURE_REF(dhe_data->Ys.data);

    /* Now we know the total size of the structure */
    data_to_verify->size = 2 + p_length + 2 + g_length + 2 + Ys_length;
    return 0;
}

int s2n_dhe_server_key_recv_parse_data(struct s2n_connection *conn, struct s2n_kex_raw_server_data *raw_server_data)
{
    struct s2n_dhe_raw_server_points dhe_data = raw_server_data->dhe_data;

    /* Copy the DH details */
    POSIX_GUARD(s2n_dh_p_g_Ys_to_dh_params(&conn->kex_params.server_dh_params, &dhe_data.p, &dhe_data.g, &dhe_data.Ys));
    return 0;
}

int s2n_server_key_send(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    S2N_ASYNC_PKEY_GUARD(conn);

    struct s2n_hash_state *signature_hash = &conn->handshake.hashes->hash_workspace;
    const struct s2n_kex *key_exchange = conn->secure->cipher_suite->key_exchange_alg;
    const struct s2n_signature_scheme *sig_scheme = conn->handshake_params.server_cert_sig_scheme;
    POSIX_ENSURE_REF(sig_scheme);
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_blob data_to_sign = { 0 };

    /* Call the negotiated key exchange method to send it's data */
    POSIX_GUARD_RESULT(s2n_kex_server_key_send(key_exchange, conn, &data_to_sign));

    /* Add common signature data */
    if (conn->actual_protocol_version == S2N_TLS12) {
        POSIX_GUARD(s2n_stuffer_write_uint16(out, sig_scheme->iana_value));
    }

    /* FIPS specifically allows MD5 for <TLS1.2 */
    if (s2n_is_in_fips_mode() && conn->actual_protocol_version < S2N_TLS12) {
        POSIX_GUARD(s2n_hash_allow_md5_for_fips(signature_hash));
    }

    /* Add the random data to the hash */
    POSIX_GUARD(s2n_hash_init(signature_hash, sig_scheme->hash_alg));
    POSIX_GUARD(s2n_hash_update(signature_hash, conn->handshake_params.client_random, S2N_TLS_RANDOM_DATA_LEN));
    POSIX_GUARD(s2n_hash_update(signature_hash, conn->handshake_params.server_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Add KEX specific data to the hash */
    POSIX_GUARD(s2n_hash_update(signature_hash, data_to_sign.data, data_to_sign.size));

    S2N_ASYNC_PKEY_SIGN(conn, sig_scheme->sig_alg, signature_hash,
            s2n_server_key_send_write_signature);
}

int s2n_ecdhe_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Generate an ephemeral key and  */
    POSIX_GUARD(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));

    /* Write it out and calculate the data to sign later */
    POSIX_GUARD(s2n_ecc_evp_write_params(&conn->kex_params.server_ecc_evp_params, out, data_to_sign));
    return 0;
}

int s2n_dhe_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Duplicate the DH key from the config */
    POSIX_GUARD(s2n_dh_params_copy(conn->config->dhparams, &conn->kex_params.server_dh_params));

    /* Generate an ephemeral key */
    POSIX_GUARD(s2n_dh_generate_ephemeral_key(&conn->kex_params.server_dh_params));

    /* Write it out and calculate the data to sign later */
    POSIX_GUARD(s2n_dh_params_to_p_g_Ys(&conn->kex_params.server_dh_params, out, data_to_sign));
    return 0;
}

int s2n_server_key_send_write_signature(struct s2n_connection *conn, struct s2n_blob *signature)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    POSIX_GUARD(s2n_stuffer_write_uint16(out, signature->size));
    POSIX_GUARD(s2n_stuffer_write_bytes(out, signature->data, signature->size));

    return 0;
}
