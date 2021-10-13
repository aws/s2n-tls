/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <cbmc_proof/nondet.h>
#include <sys/socket.h>
#include <errno.h>

/* https://pubs.opengroup.org/onlinepubs/009695399/functions/getpeername.html */
int getpeername(int socket, struct sockaddr *address, socklen_t *address_len)
{
    // assert(socket >= -1 && socket <= 65536); /* File descriptor limit. */   
    if(nondet_bool()) { return 0; }
    else {
        errno = nondet_int();
        __CPROVER_assume(errno == EBADF || errno == EINVAL || errno == ENOTCONN || errno == ENOTSOCK || errno == EOPNOTSUPP || errno == ENOBUFS);
        return -1;
    }
}
