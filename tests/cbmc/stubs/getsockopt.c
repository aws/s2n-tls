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
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* https://pubs.opengroup.org/onlinepubs/009695399/functions/getsockopt.html */
int getsockopt(int socket, int level, int option_name, void *option_value, socklen_t *option_len)
{
    /* assert(socket >= -1 && socket <= 65536); // File descriptor limit. 
    assert(level == IPPROTO_IP || level == IPPROTO_IPV6 || level == IPPROTO_ICMP || level == IPPROTO_RAW || level == IPPROTO_TCP || level == IPPROTO_UDP); 
    assert(option_name == SO_DEBUG || option_name == SO_ACCEPTCONN || option_name == SO_BROADCAST || option_name == SO_REUSEADDR || option_name == SO_KEEPALIVE || option_name == SO_LINGER || option_name == SO_OOBINLINE || option_name == SO_SNDBUF || option_name == SO_RCVBUF || option_name == SO_ERROR || option_name == SO_TYPE || option_name == SO_DONTROUTE || option_name == SO_RCVLOWAT || option_name == SO_RCVTIMEO || option_name == SO_SNDLOWAT || option_name == SO_SNDTIMEO);  */
    if(nondet_bool()) { return 0; }
    else {
        errno = nondet_int();
        __CPROVER_assume(errno == EBADF || errno == EINVAL || errno == ENOPROTOOPT || errno == ENOTSOCK || errno == EACCES || errno == ENOBUFS);
        return -1;
    }
}
