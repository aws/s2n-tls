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

#include "tls/s2n_ktls.h"

#include "tls/s2n_prf.h"

/* Used for overriding setsockopt calls in testing */
s2n_setsockopt_fn s2n_setsockopt = setsockopt;

S2N_RESULT s2n_ktls_set_setsockopt_cb(s2n_setsockopt_fn cb)
{
    RESULT_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);
    s2n_setsockopt = cb;
    return S2N_RESULT_OK;
}

bool s2n_ktls_is_supported_on_platform()
{
#if defined(S2N_KTLS_SUPPORTED)
    return true;
#else
    return false;
#endif
}

static int s2n_ktls_disabled_read(void *io_context, uint8_t *buf, uint32_t len)
{
    POSIX_BAIL(S2N_ERR_IO);
}

static S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg);
    const struct s2n_cipher *cipher = conn->secure->cipher_suite->record_alg->cipher;
    RESULT_ENSURE_REF(cipher);

    RESULT_ENSURE(s2n_ktls_is_supported_on_platform(), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);

    /* kTLS enable should only be called once the handshake has completed. */
    RESULT_ENSURE(is_handshake_complete(conn), S2N_ERR_HANDSHAKE_NOT_COMPLETE);

    /* TODO support TLS 1.3
     *
     * TLS 1.3 support requires sending the KeyUpdate message when the cryptographic
     * key usage limits are met. However, this is currently only possible by applying a
     * kernel patch to support this functionality.
     */
    RESULT_ENSURE(conn->actual_protocol_version == S2N_TLS12, S2N_ERR_KTLS_UNSUPPORTED_CONN);

    /* Check if the cipher supports kTLS */
    RESULT_ENSURE(cipher->ktls_supported, S2N_ERR_KTLS_UNSUPPORTED_CONN);

    /* kTLS I/O functionality is managed by s2n-tls. kTLS cannot be enabled if the
     * application sets custom I/O (managed_send_io == false means application has
     * set custom I/O).
     */
    switch (ktls_mode) {
        case S2N_KTLS_MODE_SEND:
            RESULT_ENSURE(conn->managed_send_io, S2N_ERR_KTLS_MANAGED_IO);
            /* The output stuffer should be empty before enabling kTLS. */
            RESULT_ENSURE(s2n_stuffer_data_available(&conn->out) == 0, S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            break;
        case S2N_KTLS_MODE_RECV:
            RESULT_ENSURE(conn->managed_recv_io, S2N_ERR_KTLS_MANAGED_IO);
            /* The input stuffer should be empty before enabling kTLS. */
            RESULT_ENSURE(s2n_stuffer_data_available(&conn->in) == 0, S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            break;
        default:
            RESULT_BAIL(S2N_ERR_SAFETY);
            break;
    }

    return S2N_RESULT_OK;
}

/* Enabling kTLS preserves the original *io_context; making this functions
 * safe to call even after kTLS has been enabled on the connection.
 *
 * Retrieving fd assumes that the connection is using socket IO and has the
 * send_io_context set. While kTLS overrides IO and essentially disables
 * the socket conn->send function callback, it doesn't modify the
 * send_io_context. */
S2N_RESULT s2n_ktls_get_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(fd);

    if (ktls_mode == S2N_KTLS_MODE_RECV) {
        RESULT_GUARD_POSIX(s2n_connection_get_read_fd(conn, fd));
    } else if (ktls_mode == S2N_KTLS_MODE_SEND) {
        RESULT_GUARD_POSIX(s2n_connection_get_write_fd(conn, fd));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ktls_get_io_mode(s2n_ktls_mode ktls_mode, int *tls_tx_rx_mode)
{
    RESULT_ENSURE_REF(tls_tx_rx_mode);

    if (ktls_mode == S2N_KTLS_MODE_SEND) {
        *tls_tx_rx_mode = S2N_TLS_TX;
    } else {
        *tls_tx_rx_mode = S2N_TLS_RX;
    }
    return S2N_RESULT_OK;
}

#if defined(S2N_KTLS_SUPPORTED)
S2N_RESULT s2n_ktls_init_aes128_gcm_crypto_info(struct s2n_connection *conn, s2n_ktls_mode ktls_mode,
        struct s2n_key_material *key_material, struct tls12_crypto_info_aes_gcm_128 *crypto_info)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->client);
    RESULT_ENSURE_REF(conn->server);
    RESULT_ENSURE_REF(key_material);
    RESULT_ENSURE_REF(crypto_info);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg);
    const struct s2n_cipher *cipher = conn->secure->cipher_suite->record_alg->cipher;
    RESULT_ENSURE_REF(cipher);

    RESULT_ENSURE(cipher == &s2n_aes128_gcm, S2N_ERR_KTLS_UNSUPPORTED_CONN);
    RESULT_ENSURE(conn->actual_protocol_version == S2N_TLS12, S2N_ERR_KTLS_UNSUPPORTED_CONN);
    crypto_info->info.cipher_type = TLS_CIPHER_AES_GCM_128;
    crypto_info->info.version = TLS_1_2_VERSION;

    /* set values based on mode of operation */
    struct s2n_blob *key = NULL;
    struct s2n_blob implicit_iv = { 0 };
    struct s2n_blob sequence_number = { 0 };

    bool server_sending = (conn->mode == S2N_SERVER && ktls_mode == S2N_KTLS_MODE_SEND);
    bool client_receiving = (conn->mode == S2N_CLIENT && ktls_mode == S2N_KTLS_MODE_RECV);
    if (server_sending || client_receiving) {
        /* If server is sending or client is receiving then use server key material */
        key = &key_material->server_key;
        RESULT_GUARD_POSIX(s2n_blob_init(&implicit_iv, conn->server->server_implicit_iv, sizeof(conn->server->server_implicit_iv)));
        RESULT_GUARD_POSIX(s2n_blob_init(&sequence_number, conn->server->server_sequence_number, sizeof(conn->server->server_sequence_number)));
    } else {
        key = &key_material->client_key;
        RESULT_GUARD_POSIX(s2n_blob_init(&implicit_iv, conn->client->client_implicit_iv, sizeof(conn->client->client_implicit_iv)));
        RESULT_GUARD_POSIX(s2n_blob_init(&sequence_number, conn->client->client_sequence_number, sizeof(conn->client->client_sequence_number)));
    }

    /* The salt is the first 4 bytes of the IV.
     *
     *= https://www.rfc-editor.org/rfc/rfc4106#section-4
     *# The salt field is a four-octet value that is assigned at the
     *# beginning of the security association, and then remains constant
     *# for the life of the security association.
     */
    RESULT_ENSURE_GTE(implicit_iv.size, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info->salt, implicit_iv.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    RESULT_ENSURE_GTE(implicit_iv.size, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info->iv, implicit_iv.data, TLS_CIPHER_AES_GCM_128_IV_SIZE);

    RESULT_ENSURE_EQ(sequence_number.size, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info->rec_seq, sequence_number.data, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

    RESULT_ENSURE_EQ(key->size, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info->key, key->data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    return S2N_RESULT_OK;
}
#endif

static S2N_RESULT s2n_ktls_set_keys(struct s2n_connection *conn, s2n_ktls_mode ktls_mode,
        struct s2n_key_material *key_material)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(key_material);

    int fd = 0;
    RESULT_GUARD(s2n_ktls_get_file_descriptor(conn, ktls_mode, &fd));

    int tls_tx_rx_mode = 0;
    RESULT_GUARD(s2n_ktls_get_io_mode(ktls_mode, &tls_tx_rx_mode));
#if defined(S2N_KTLS_SUPPORTED)
    /* Only AES_128_GCM for TLS 1.2 is supported at the moment. */
    struct tls12_crypto_info_aes_gcm_128 crypto_info = { 0 };
    RESULT_GUARD(s2n_ktls_init_aes128_gcm_crypto_info(conn, ktls_mode, key_material, &crypto_info));

    /* Set crypto_info on the socket; enabling kTLS and offloading the TLS
     * protocol to the kernel. */
    int ret = s2n_setsockopt(fd, S2N_SOL_TLS, tls_tx_rx_mode, &crypto_info, sizeof(crypto_info));
    if (ret < 0) {
        RESULT_BAIL(S2N_ERR_KTLS_ENABLE_CRYPTO);
    }
#endif

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ktls_configure_socket(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);

    int fd = 0;
    RESULT_GUARD(s2n_ktls_get_file_descriptor(conn, ktls_mode, &fd));
    /* Enable 'tls' ULP for the socket. https://lwn.net/Articles/730207
     *
     * Its not possible to detect kTLS support at compile time. We need rely on
     * the call to setsockopt(..TCP_ULP...) to determine if kTLS is supported.
     * This is a safe and non destructive operation on Linux.
     */
    int ret = s2n_setsockopt(fd, S2N_SOL_TCP, S2N_TCP_ULP, S2N_TLS_ULP_NAME, S2N_TLS_ULP_NAME_SIZE);
    if (ret < 0) {
        /* https://github.com/torvalds/linux/blob/831fe284d8275987596b7d640518dddba5735f61/net/ipv4/tcp_ulp.c#L64-L65
         *
         * EEXIST indicates that TCP_ULP has already been enabled on the
         * socket. This is a noop and therefore safe to ignore.
         */
        RESULT_ENSURE(errno == EEXIST, S2N_ERR_KTLS_ULP);
    }

    /* configure crypto */
    struct s2n_key_material key_material = { 0 };
    RESULT_GUARD(s2n_prf_generate_key_material(conn, &key_material));
    RESULT_GUARD(s2n_ktls_set_keys(conn, ktls_mode, &key_material));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_configure_connection(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    if (ktls_mode == S2N_KTLS_MODE_SEND) {
        conn->ktls_send_enabled = true;
        conn->send = s2n_ktls_send_cb;
    } else {
        conn->ktls_recv_enabled = true;
        conn->recv = s2n_ktls_disabled_read;
    }
    return S2N_RESULT_OK;
}

/*
 * Since kTLS is an optimization, it is possible to continue operation
 * by using userspace TLS if kTLS is not supported.
 *
 * kTLS configuration errors are recoverable since calls to setsockopt are
 * non-destructive and its possible to fallback to userspace.
 */
int s2n_connection_ktls_enable_send(struct s2n_connection *conn)
{
    /* gate this feature only to tests until it is ready for release */
    POSIX_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD_RESULT(s2n_ktls_validate(conn, S2N_KTLS_MODE_SEND));

    /* If already enabled then return success */
    if (conn->ktls_send_enabled) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_SEND));
    POSIX_GUARD_RESULT(s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_SEND));

    return S2N_SUCCESS;
}

int s2n_connection_ktls_enable_recv(struct s2n_connection *conn)
{
    /* gate this feature only to tests until it is ready for release */
    POSIX_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD_RESULT(s2n_ktls_validate(conn, S2N_KTLS_MODE_RECV));

    /* If already enabled then return success */
    if (conn->ktls_recv_enabled) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_RECV));
    POSIX_GUARD_RESULT(s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV));

    return S2N_SUCCESS;
}
