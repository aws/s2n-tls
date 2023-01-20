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

#include <errno.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bits/stdint-uintn.h"
#include "utils/s2n_result.h"
#define SOL_TCP 6

#include "api/s2n.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety_macros.h"
#include "utils/s2n_socket.h"

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
/*     RESULT_CHECKED_MEMCPY(crypto_info.iv, conn->client->client_sequence_number, TLS_CIPHER_AES_GCM_128_IV_SIZE); */

/*     /1* tls 1.3 *1/ */
/*     /1* ... *1/ */

/*     /1* common *1/ */
/*     RESULT_CHECKED_MEMCPY(crypto_info.salt, conn->client->client_implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE); */
/*     RESULT_CHECKED_MEMCPY(crypto_info.rec_seq, conn->client->client_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE); */
/*     RESULT_CHECKED_MEMCPY(crypto_info.key, tls12_secret.master_secret, TLS_CIPHER_AES_GCM_128_KEY_SIZE); */

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
/*         return S2N_RESULT_ERROR; */
/*     } else { */
/*         fprintf(stdout, "ktls RX keys set---------- \n"); */
/*     } */

/*     return S2N_SUCCESS; */
/* } */
/* send TLS control message using record_type */

S2N_RESULT s2n_klts_send_ctrl_msg(int sock, uint8_t record_type, void *data, size_t length)
{
    struct msghdr   msg      = { 0 };
    int             cmsg_len = sizeof(record_type);
    struct cmsghdr *cmsg;
    char            buf[ CMSG_SPACE(cmsg_len) ];
    struct iovec    msg_iov; /* Vector of data to send/receive into.  */

    msg.msg_control    = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg               = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level   = SOL_TLS;
    cmsg->cmsg_type    = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len     = CMSG_LEN(cmsg_len);
    *CMSG_DATA(cmsg)   = TLS_ALERT;
    msg.msg_controllen = cmsg->cmsg_len;

    msg_iov.iov_base = data;
    msg_iov.iov_len  = length;
    msg.msg_iov      = &msg_iov;
    msg.msg_iovlen   = 1;

    int ret_val = sendmsg(sock, &msg, 0);
    if (ret_val < 0) {
        fprintf(stderr, "ktls send cmsg xxxxxxxxxxxxxx: type: %d, errno %s\n", record_type, strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls send cmsg ---------- : type: %d\n", record_type);
    }

    return S2N_RESULT_OK;
}

int s2n_ktls_write_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(buf);
    int wfd = (( struct s2n_ktls_write_io_context * )io_context)->fd;
    if (wfd < 0) {
        errno = EBADF;
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }

    /* On success, the number of bytes written is returned. On failure, -1 is
     * returned and errno is set appropriately. */

    /* fprintf(stdout, "ktls writing---------- len: %d\n", len); */
    ssize_t result = write(wfd, buf, len);
    /* fprintf(stdout, "ktls writing done---------- result: %zd\n", result); */
    POSIX_ENSURE_INCLUSIVE_RANGE(INT_MIN, result, INT_MAX);
    return result;
}

int s2n_connection_set_ktls_write_fd(struct s2n_connection *conn, int wfd)
{
    struct s2n_blob                   ctx_mem = { 0 };
    struct s2n_ktls_write_io_context *peer_ktls_ctx;

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_ktls_write_io_context)));

    peer_ktls_ctx                  = ( struct s2n_ktls_write_io_context                  *)( void                  *)ctx_mem.data;
    peer_ktls_ctx->fd              = wfd;
    peer_ktls_ctx->ktls_socket_set = true;

    POSIX_GUARD(s2n_connection_set_send_cb(conn, s2n_ktls_write_fn));
    POSIX_GUARD(s2n_connection_set_send_ctx(conn, peer_ktls_ctx));
    conn->managed_send_io = true;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    POSIX_GUARD(s2n_socket_write_snapshot(conn));

    uint8_t ipv6;
    if (0 == s2n_socket_is_ipv6(wfd, &ipv6)) { conn->ipv6 = (ipv6 ? 1 : 0); }

    conn->write_fd_broken = 0;

    return 0;
}

/* currently only handles tls 1.2 */
S2N_RESULT s2n_ktls_tx_keys(struct s2n_connection *conn, int fd, uint8_t implicit_iv[ S2N_TLS_MAX_IV_LEN ],
                            uint8_t sequence_number[ S2N_TLS_SEQUENCE_NUM_LEN ], uint8_t key[ 16 ])
{
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    RESULT_CHECKED_MEMCPY(crypto_info.salt, implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.rec_seq, sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    if (conn->actual_protocol_version == S2N_TLS12) {
        crypto_info.info.version = TLS_1_2_VERSION;
        RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    } else if (conn->actual_protocol_version == S2N_TLS13) {
        crypto_info.info.version = TLS_1_3_VERSION;

        /* RESULT_ENSURE_EQ(sizeof(implicit_iv), TLS_CIPHER_AES_GCM_128_SALT_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE); */

        /* memcpy (crypto_info.iv, iv.data + TLS_CIPHER_AES_GCM_128_SALT_SIZE, */
        /* TLS_CIPHER_AES_GCM_128_IV_SIZE); */
        RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
                              TLS_CIPHER_AES_GCM_128_IV_SIZE);
    } else {
        fprintf(stderr, "ktls only supported for tls1.2 and tls1.3 xxxxxxxxxxxxxx: %d\n",
                conn->actual_protocol_version);
    }

    /* set keys */
    int ret_val = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
    if (ret_val < 0) {
        fprintf(stderr, "ktls set TX key 3 xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls TX keys set---------- \n");
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_set_keys(struct s2n_connection *conn, int fd)
{
    RESULT_ENSURE_REF(conn);

    if (conn->mode == S2N_SERVER) {
        RESULT_ENSURE_EQ(sizeof(conn->server_key), TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        RESULT_GUARD(s2n_ktls_tx_keys(conn, fd, conn->server->server_implicit_iv, conn->server->server_sequence_number,
                                      conn->server_key));
    } else {
        RESULT_ENSURE_EQ(sizeof(conn->client_key), TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        RESULT_GUARD(s2n_ktls_tx_keys(conn, fd, conn->client->client_implicit_iv, conn->client->client_sequence_number,
                                      conn->client_key));
    }

    RESULT_GUARD_POSIX(s2n_connection_set_ktls_write_fd(conn, fd));

    /* char filename[] = "sample.txt"; */
    /* int send_times = 1000000; // 2gb */

    /* char filename[] = "sample.txt.500b"; */
    /* int send_times = 4000000; // 2gb */
    /* char filename[] = "sample.txt.1k"; */
    /* int send_times = 2000000; // 2gb */
    /* char filename[] = "sample.txt.2k"; */
    /* int send_times = 1000000; // 2gb */
    /* char filename[] = "sample.txt.4k"; */
    /* int  send_times = 500000;  // 2gb */
    /* char filename[] = "sample.txt.8k"; */
    /* int send_times = 250000; // 2gb */
    /* char filename[] = "sample.txt.16k"; */
    /* int send_times = 125000; // 2gb */
    /* char filename[] = "sample.txt.33k"; */
    /* int send_times = 60600; // 2gb */
    /* char filename[] = "sample.txt.67k"; */
    /* int send_times = 30300; // 2gb */
    /* char filename[] = "sample.txt.133k"; */
    /* int send_times = 15000; // 2gb */
    /* char filename[] = "sample.txt.266k"; */
    /* int send_times = 7500; // 2gb */
    /* char filename[] = "sample.txt.400k"; */
    /* int send_times = 5000; // 2gb */
    /* char filename[] = "sample.txt.4m"; */
    /* int send_times = 500; // 2gb */
    /* fprintf(stderr, "starting sendfile -------------- file: %s times: %d \n", filename, send_times); */

    /* if (conn->mode == S2N_CLIENT) { */
    /*     for (int i = 0; i <= send_times; i++) { */
    /*         int         fd1; */
    /*         struct stat stbuf; */
    /*         /1* open *1/ */
    /*         if ((fd1 = open(filename, O_RDWR)) < 0) { */
    /*             fprintf(stderr, "error open file sample.txt xxxxxxxxxxxxxx  %s\n", strerror(errno)); */
    /*         } */

    /*         fstat(fd1, &stbuf); */
    /*         /1* fprintf(stderr, "file of size sent -------------- %ld\n", stbuf.st_size); *1/ */
    /*         int rv; */
    /*         /1* sendfile *1/ */
    /*         if ((rv = sendfile(fd, fd1, 0, stbuf.st_size)) < 0) { */
    /*             fprintf(stderr, "error sendfile xxxxxxxxxxxxxx  %d %s\n", rv, strerror(errno)); */
    /*         } */
    /*     } */
    /* } */
    /* fprintf(stderr, "file sent -------------- \n"); */

    /* send plaintext since we are using ktls */
    /* { */
    /*     const char *msg = "hello world\n"; */
    /*     int ret_val = write(fd, msg, strlen(msg)); */
    /*     if (ret_val < 0) { */
    /*         fprintf(stderr, "ktls write failed 5 xxxxxxxxxxxxxx: %s\n", strerror(errno)); */
    /*         return S2N_RESULT_ERROR; */
    /*     } else { */
    /*         fprintf(stdout, "ktls wrote hello world success---------- \n"); */
    /*     } */
    /* } */

    /* send alert via ktls */
    /* { */
    /*     int s2n_tls_alert_level_fatal = 2; */
    /*     uint8_t alert[2]; */
    /*     alert[0] = s2n_tls_alert_level_fatal; */
    /*     alert[1] = S2N_TLS_ALERT_CLOSE_NOTIFY; */
    /*     RESULT_GUARD(s2n_klts_send_ctrl_msg(fd, TLS_ALERT, alert, S2N_ALERT_LENGTH)); */
    /* } */

    conn->ktls_enabled_send_io = true;

    return S2N_RESULT_OK;
}

/* Enable the "tls" Upper Level Protocols (ULP) over TCP for this connection */
S2N_RESULT s2n_ktls_register_ulp(int fd)
{
    // todo see if this is already done
    int ret_val = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret_val < 0) {
        fprintf(stderr, "ktls register upl failed 2 xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls upl enabled---------- \n");
    }

    return S2N_RESULT_OK;
}

// todo
// - RX mode
// - cleanup if intermediate steps fails
S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_EQ(conn->config->ktls_requested, true);

    /* RESULT_ENSURE_EQ(conn->managed_send_io, true); */
    /* RESULT_ENSURE_EQ(conn->managed_recv_io, true); */

    /* should not be called twice */
    RESULT_ENSURE_EQ(conn->ktls_enabled_send_io, false);
    RESULT_ENSURE_EQ(conn->ktls_enabled_recv_io, false);

    /* const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context; */
    int fd = conn->sendfd;
    /* int fd = 8; */
    fprintf(stderr, "ktls upl for socket fd---------- %d\n", conn->sendfd);

    /* register the tls ULP */
    RESULT_GUARD(s2n_ktls_register_ulp(fd));

    /* set keys */
    RESULT_GUARD(s2n_ktls_set_keys(conn, fd));

    /* conn->ktls_enabled_recv_io = true; */

    return S2N_RESULT_OK;
}

int s2n_connection_ktls_switch_keys(struct s2n_connection *conn)
{
    /*     if (conn->mode == S2N_SERVER) { */
    /*         return S2N_FAILURE; */
    /*     } */

    /*     POSIX_ENSURE_REF(conn); */
    /*     POSIX_ENSURE_EQ(conn->config->ktls_requested, true); */
    /*     POSIX_ENSURE_EQ(conn->ktls_enabled_send_io, true); */

    /*     const struct s2n_ktls_write_io_context *peer_ktls_ctx = conn->send_io_context; */
    /*     int fd = peer_ktls_ctx->fd; */

    /*     POSIX_GUARD_RESULT(s2n_ktls_register_ulp(fd)); */

    /*     POSIX_GUARD_RESULT(s2n_ktls_client_tx_keys(conn, fd, true)); */

    return S2N_SUCCESS;
}
