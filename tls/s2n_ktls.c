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
/*         fprintf(stderr, "ktls RX tls key 3: %s\n", strerror(errno)); */
/*         /1* exit(1); *1/ */
/*     } else { */
/*         fprintf(stdout, "ktls RX keys set---------- \n"); */
/*     } */

/*     return S2N_SUCCESS; */
/* } */

/* int s2n_ktls_tx_keys(struct s2n_connection *conn) { */
/*     struct tls12_crypto_info_aes_gcm_128 crypto_info; */
/*     memset(&crypto_info, 0, sizeof(crypto_info)); */
/*     crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128; */

/*     struct s2n_tls12_secrets tls12_secret = conn->secrets.tls12; */
/*     /1* uint8_t s = sizeof(tls12_secret.master_secret); *1/ */
/*     POSIX_ENSURE_EQ(16, TLS_CIPHER_AES_GCM_128_KEY_SIZE); */

/*     /1* tls 1.2 *1/ */
/*     crypto_info.info.version = TLS_1_2_VERSION; */
/*     memcpy(crypto_info.iv, conn->server->server_sequence_number, TLS_CIPHER_AES_GCM_128_IV_SIZE); */

/*     /1* tls 1.3 *1/ */
/*     /1* ... *1/ */

/*     /1* common *1/ */
/*     memcpy(crypto_info.salt, conn->server->server_implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE); */
/*     memcpy(crypto_info.rec_seq, conn->server->server_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE); */
/*     memcpy(crypto_info.key, tls12_secret.master_secret, TLS_CIPHER_AES_GCM_128_KEY_SIZE); */

/*     /1* check managed_send_io *1/ */
/*     struct s2n_socket_write_io_context *w_io_ctx = (struct s2n_socket_write_io_context *) conn->send_io_context; */
/*     int ret_val = setsockopt(w_io_ctx->fd, SOL_TLS, TLS_TX, &crypto_info, sizeof (crypto_info)); */
/*     if (ret_val < 0) { */
/*         fprintf(stderr, "ktls TX tls key 3: %s\n", strerror(errno)); */
/*         /1* exit(1); *1/ */
/*     } else { */
/*         fprintf(stdout, "ktls TX keys set---------- \n"); */
/*     } */

/*     return S2N_SUCCESS; */
/* } */

S2N_RESULT s2n_ktls_set_keys(struct s2n_connection *conn) {
    RESULT_ENSURE_REF(conn);

    // TODO
    /* // check if we want to enable write */
    /* POSIX_GUARD(s2n_ktls_tx_keys(conn)); */
    /* s2n_connection_set_write_fd(conn, conn->ktls_write_fd); */

    /* // check if we want to enable read */
    /* POSIX_GUARD(s2n_ktls_rx_keys(conn)); */
    /* s2n_connection_set_read_fd(conn, conn->ktls_read_fd); */

    return S2N_RESULT_OK;
}

/* Enable the "tls" Upper Level Protocols (ULP) over TCP for this connection */
S2N_RESULT s2n_ktls_register_ulp(struct s2n_connection *conn) {
    RESULT_ENSURE_REF(conn);

    const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context;

    // TODO support client mode
    if (conn->mode == S2N_CLIENT) {
        return S2N_RESULT_ERROR;
    }

    // TODO see if this is already done
    int ret_val = setsockopt(peer_socket_ctx->fd, SOL_TCP, TCP_ULP, "tls", sizeof ("tls"));
    if (ret_val < 0) {
        fprintf(stderr, "ktls enable failed 2: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
        /* exit(1); */
    } else {
        fprintf(stdout, "ktls enabled---------- \n");
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn) {
    RESULT_ENSURE_REF(conn);

    /* register the tls ULP */
    RESULT_GUARD(s2n_ktls_register_ulp(conn));

    /* set keys */
    RESULT_GUARD(s2n_ktls_set_keys(conn));

    conn->ktls_enabled_send_io = true;

    return S2N_RESULT_OK;
}
