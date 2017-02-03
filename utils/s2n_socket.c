/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <tls/s2n_connection.h>

#include <utils/s2n_socket.h>
#include <utils/s2n_safety.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>

#if TCP_CORK
    #define S2N_CORK        TCP_CORK
    #define S2N_CORK_ON     1
    #define S2N_CORK_OFF    0
#elif TCP_NOPUSH   
    #define S2N_CORK        TCP_NOPUSH
    #define S2N_CORK_ON     1
    #define S2N_CORK_OFF    0
#elif TCP_NODELAY
    #define S2N_CORK        TCP_NODELAY
    #define S2N_CORK_ON     0
    #define S2N_CORK_OFF    1
#endif

int s2n_socket_write_snapshot(struct s2n_connection *conn)
{
#ifdef S2N_CORK
    socklen_t corklen = sizeof(int);

    getsockopt(conn->writefd, IPPROTO_TCP, S2N_CORK, &conn->original_cork_val, &corklen);
    eq_check(corklen, sizeof(int));
    conn->original_cork_is_set = 1;
#endif

    return 0;
}


int s2n_socket_read_snapshot(struct s2n_connection *conn)
{
#ifdef SO_RCVLOWAT
    socklen_t watlen = sizeof(int);

    getsockopt(conn->readfd, IPPROTO_TCP, SO_RCVLOWAT, &conn->original_rcvlowat_val, &watlen);
    eq_check(watlen, sizeof(int));
    conn->original_rcvlowat_is_set = 1;
#endif

    return 0;
}

int s2n_socket_write_restore(struct s2n_connection *conn)
{
#ifdef S2N_CORK
    if (!conn->original_cork_is_set) {
        return 0;
    }
    setsockopt(conn->writefd, IPPROTO_TCP, S2N_CORK, &conn->original_cork_val, sizeof(conn->original_cork_val));
    conn->original_cork_is_set = 0;
#endif

    return 0;
}

int s2n_socket_read_restore(struct s2n_connection *conn)
{
#ifdef SO_RCVLOWAT
   if (!conn->original_rcvlowat_is_set) {
        return 0;
    }
    setsockopt(conn->readfd, IPPROTO_TCP, SO_RCVLOWAT, &conn->original_rcvlowat_val, sizeof(conn->original_rcvlowat_val));
    conn->original_rcvlowat_is_set = 0;
#endif

    return 0;
}

int s2n_socket_write_cork(struct s2n_connection *conn)
{
#ifdef S2N_CORK
    int optval = S2N_CORK_ON;

    /* Ignore the return value, if it fails it fails */
    setsockopt(conn->writefd, IPPROTO_TCP, S2N_CORK, &optval, sizeof(optval));
#endif
    
    return 0;
}

int s2n_socket_write_uncork(struct s2n_connection *conn)
{
#ifdef S2N_CORK
    int optval = S2N_CORK_OFF;

    /* Ignore the return value, if it fails it fails */
    setsockopt(conn->writefd, IPPROTO_TCP, S2N_CORK, &optval, sizeof(optval));
#endif
 
    return 0;
}

int s2n_socket_set_read_size(struct s2n_connection *conn, int size)
{
#ifdef SO_RCVLOWAT
    setsockopt(conn->writefd, IPPROTO_TCP, SO_RCVLOWAT, &size, sizeof(size));
#endif

    return 0;
}
