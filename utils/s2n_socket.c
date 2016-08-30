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

int s2n_socket_cork(struct s2n_connection *conn)
{
#ifdef S2N_CORK
    int optval = S2N_CORK_ON;

    /* Ignore the return value, if it fails it fails */
    setsockopt(conn->writefd, IPPROTO_TCP, S2N_CORK, &optval, sizeof(optval));
#endif
    
    return 0;
}

int s2n_socket_uncork(struct s2n_connection *conn)
{
#ifdef S2N_CORK
    int optval = S2N_CORK_OFF;

    /* Ignore the return value, if it fails it fails */
    setsockopt(conn->writefd, IPPROTO_TCP, S2N_CORK, &optval, sizeof(optval));
#endif
 
    return 0;
}

