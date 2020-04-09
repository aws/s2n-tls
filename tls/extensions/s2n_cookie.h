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
#include "stuffer/s2n_stuffer.h"

/* Return the length of cookie data in the connection */
int s2n_extensions_cookie_size(struct s2n_connection *conn);

/* Write the connection's cookie data to the output stuffer */
int s2n_extensions_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out);

/* Read cookie data out of the received extension, and save it in the connection */
int s2n_extensions_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

/* Functions specific to the server/client side cookie operations */
int s2n_extensions_server_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out);
int s2n_extensions_server_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);
int s2n_extensions_client_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out);
int s2n_extensions_client_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);
