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

#pragma once

#include "tls/s2n_connection.h"

/* /1* The default write I/O context for communication over a ktls socket *1/ */
/* struct s2n_ktls_write_io_context { */
/*     /1* The peer's fd *1/ */
/*     int fd; */

/*     /1* User requested ktls enable. *1/ */
/*     /1* TODO: this should live on the config rather on the connection. *1/ */
/*     /1* unsigned int ktls_requested:1; *1/ */

/*     /1* The TCP socket has been made TLS aware. *1/ */
/*     unsigned int ktls_socket_set:1; */

/*     /1* ktls is enabled for this connection. *1/ */
/*     unsigned int ktls_enabled:1; */
/* }; */

/* /1* TODO: wip. implement the write first. *1/ */
/* /1* The default read I/O context for communication over a ktls socket *1/ */
/* struct s2n_ktls_read_io_context { */
/*     /1* The peer's fd *1/ */
/*     int fd; */
/* }; */

/* /1* typedef int s2n_send_fn(void *io_context, const uint8_t *buf, uint32_t len); *1/ */
/* int s2n_ktls_write(void *io_context, const uint8_t *buf, uint32_t len); */

/* /1* typedef int s2n_recv_fn(void *io_context, uint8_t *buf, uint32_t len); *1/ */
/* int s2n_ktls_recv(void *io_context, const uint8_t *buf, uint32_t len); */

/* record_type: type of  */
/* TLS_APPLICATION_DATA */
/* int s2n_ktls_send_control_msg(struct s2n_connection *conn, uint8_t record_type, void *data, size_t data_size); */
/* int s2n_ktls_recv_control_msg(struct s2n_connection *conn, uint8_t record_type, void *data, size_t data_size); */




/* Enables ktls for the connection.
 *
 * ktls assumes that the application has not set custom IO. Failure of this
 * function call should generally not be treated as a fatal error since a
 * a connection can continue to operate even if ktls is not enabled.
 */
S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn);

