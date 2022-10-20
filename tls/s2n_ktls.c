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

#include <linux/tls.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <stdio.h>
#include <string.h>
#include "utils/s2n_result.h"
#define SOL_TCP        6

#include "api/s2n.h"
#include "tls/s2n_ktls.h"

#include "utils/s2n_safety_macros.h"
#include "utils/s2n_socket.h"
#include "utils/s2n_safety.h"

/* int s2n_ktls_rx_keys(struct s2n_connection *conn) { */
/*     struct tls12_crypto_info_aes_gcm_128 crypto_info; */

/*     memset(&crypto_info, 0, sizeof(crypto_info)); */

/* 		crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128; */

/*     struct s2n_tls12_secrets tls12_secret = conn->secrets.tls12; */
/*     /1* uint8_t s = sizeof(tls12_secret.master_secret); *1/ */
/*     POSIX_ENSURE_EQ(16, TLS_CIPHER_AES_GCM_128_KEY_SIZE); */

/* 		/1* for TLS 1.2 IV is generated in kernel *1/ */
/*     /1* tls 1.2 *1/ */
/*     crypto_info.info.version = TLS_1_2_VERSION; */
/*     memcpy(crypto_info.iv, conn->server->server_sequence_number, TLS_CIPHER_AES_GCM_128_IV_SIZE); */

/*     /1* tls 1.3 *1/ */
/*     /1* ... *1/ */

/*     /1* common *1/ */
/*     memcpy(crypto_info.salt, conn->server->server_implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE); */
/*     memcpy(crypto_info.rec_seq, conn->server->server_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE); */
/*     memcpy(crypto_info.key, tls12_secret.master_secret, TLS_CIPHER_AES_GCM_128_KEY_SIZE); */

/* 				/1* if (setsockopt (sockin, SOL_TLS, TLS_RX, *1/ */
/* 				/1* 		&crypto_info, sizeof (crypto_info))) { *1/ */
/* 				/1* 	session->internals.ktls_enabled &= ~GNUTLS_KTLS_RECV; *1/ */
/* 				/1* 	return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR); *1/ */
/* 				/1* } *1/ */

/*     /1* check managed_send_io *1/ */
/*     struct s2n_socket_read_io_context *r_io_ctx = (struct s2n_socket_read_io_context *) conn->recv_io_context; */
/*     int ret_val = setsockopt(r_io_ctx->fd, SOL_TLS, TLS_RX, &crypto_info, sizeof (crypto_info)); */
/*     if (ret_val < 0) { */
/*         fprintf(stderr, "ktls set RX key 3 xxxxxxxxxxxxxx: %s\n", strerror(errno)); */
/*         /1* exit(1); *1/ */
/*     } else { */
/*         fprintf(stdout, "ktls RX keys set---------- \n"); */
/*     } */

/*     return S2N_SUCCESS; */
/* } */

S2N_RESULT s2n_ktls_tx_keys(struct s2n_connection *conn, int fd) {
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    struct s2n_tls12_secrets tls12_secret = conn->secrets.tls12;
    /* uint8_t s = sizeof(tls12_secret.master_secret); */
    RESULT_ENSURE_EQ(16, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    /* tls 1.2 */
    crypto_info.info.version = TLS_1_2_VERSION;
    memcpy(crypto_info.iv, conn->server->server_sequence_number, TLS_CIPHER_AES_GCM_128_IV_SIZE);

    /* tls 1.3 */
    /* ... */

    /* common */
    memcpy(crypto_info.salt, conn->server->server_implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memcpy(crypto_info.rec_seq, conn->server->server_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info.key, tls12_secret.master_secret, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    /* set keys */
    int ret_val = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
    if (ret_val < 0) {
        fprintf(stderr, "ktls set TX key 3 xxxxxxxxxxxxxx: %s\n", strerror(errno));
        /* exit(1); */
    } else {
        fprintf(stdout, "ktls TX keys set---------- \n");
    }

    return S2N_RESULT_OK;
}

int s2n_ktls_write_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(buf);
    int wfd = ((struct s2n_ktls_write_io_context*) io_context)->fd;
    if (wfd < 0) {
        errno = EBADF;
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }

    /* On success, the number of bytes written is returned. On failure, -1 is
     * returned and errno is set appropriately. */

    fprintf(stdout, "ktls writing---------- \n");
    ssize_t result = write(wfd, buf, len);
    fprintf(stdout, "ktls writing done---------- \n");
    POSIX_ENSURE_INCLUSIVE_RANGE(INT_MIN, result, INT_MAX);
    return result;
}

int s2n_connection_set_ktls_write_fd(struct s2n_connection *conn, int wfd)
{
    struct s2n_blob ctx_mem = {0};
    struct s2n_ktls_write_io_context *peer_ktls_ctx;

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_ktls_write_io_context)));

    peer_ktls_ctx = (struct s2n_ktls_write_io_context *)(void *)ctx_mem.data;
    peer_ktls_ctx->fd = wfd;
    peer_ktls_ctx->ktls_socket_set = true;
    peer_ktls_ctx->ktls_enabled = true;

    POSIX_GUARD(s2n_connection_set_send_cb(conn, s2n_ktls_write_fn));
    POSIX_GUARD(s2n_connection_set_send_ctx(conn, peer_ktls_ctx));
    conn->managed_send_io = true;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    POSIX_GUARD(s2n_socket_write_snapshot(conn));

    uint8_t ipv6;
    if (0 == s2n_socket_is_ipv6(wfd, &ipv6)) {
        conn->ipv6 = (ipv6 ? 1 : 0);
    }

    conn->write_fd_broken = 0;

    return 0;
}

S2N_RESULT s2n_ktls_set_keys(struct s2n_connection *conn, int fd) {
    RESULT_ENSURE_REF(conn);

    // TODO!!!!!!!!!! setting the keys and
    // set write fd with ktls io and context
    RESULT_GUARD(s2n_ktls_tx_keys(conn, fd));

    const char *msg = "hello world\n";
    int ret_val = write(fd, msg, strlen(msg));
    if (ret_val < 0) {
        fprintf(stderr, "ktls write failed 5 xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stdout, "ktls wrote hello world success---------- \n");
    }

    /* RESULT_GUARD_POSIX(s2n_connection_set_ktls_write_fd(conn, fd)); */

    /* // check if we want to enable read */
    /* POSIX_GUARD(s2n_ktls_rx_keys(conn)); */
    /* s2n_connection_set_read_fd(conn, conn->ktls_read_fd); */

    return S2N_RESULT_OK;
}

/* Enable the "tls" Upper Level Protocols (ULP) over TCP for this connection */
S2N_RESULT s2n_ktls_register_ulp(int fd) {
    // todo see if this is already done
    int ret_val = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret_val < 0) {
        fprintf(stderr, "ktls register upl failed 2 xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
        /* exit(1); */
    } else {
        fprintf(stdout, "ktls upl enabled---------- \n");
    }

    return S2N_RESULT_OK;
}

// todo
// - add server mode
// - RX mode
// - cleanup if intermediate steps fails
S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn) {
    if (conn->mode == S2N_SERVER) {
        return S2N_RESULT_ERROR;
    }

    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_EQ(conn->managed_send_io, true);
    /* RESULT_ENSURE_EQ(conn->managed_recv_io, true); */

    /* should not be called twice */
    RESULT_ENSURE_EQ(conn->ktls_enabled_send_io, false);
    RESULT_ENSURE_EQ(conn->ktls_enabled_recv_io, false);

    const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context;
    int fd = peer_socket_ctx->fd;

    /* register the tls ULP */
    RESULT_GUARD(s2n_ktls_register_ulp(fd));

    /* set keys */
    RESULT_GUARD(s2n_ktls_set_keys(conn, fd));

    conn->ktls_enabled_send_io = true;
    /* conn->ktls_enabled_recv_io = true; */

    return S2N_RESULT_OK;
}
