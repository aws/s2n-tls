/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "tls/s2n_kex.h"
#include "utils/s2n_blob.h"

/*
 * The below methods are used to read in the specific key exchange messages from the connection. They take no action on
 * the data and rely on the caller to verify the data.
 * conn: in parameter which is the current connection
 * data_to_verify: out parameter that is the data required to be added to the signature hash to be used for verifying the data
 * kex_data: out parameter that is the temporary, unverified key exchange data, this will be passed to the corresponding parse method
 */
int s2n_dhe_server_key_recv_read_data(struct s2n_connection *conn, struct s2n_blob *data_to_verify, union s2n_kex_server_data *kex_data);
int s2n_ecdhe_server_key_recv_read_data(struct s2n_connection *conn, struct s2n_blob *data_to_verify, union s2n_kex_server_data *kex_data);
int s2n_rsa_server_key_recv_read_data(struct s2n_connection *conn, struct s2n_blob *data_to_verify, union s2n_kex_server_data *kex_data);

/*
 * The below methods are used to parse the specific key exchange data, it does not read data from the connection.
 * They are to be used by the client to handle parsing the server's portion of the key exchange. They are not
 * responsible for verifying the response or reading the signature from the connection.
 *
 * conn: in parameter which is the current connection
 * kex_data: in parameter that is the verified key exchange data to be used
 */
int s2n_dhe_server_key_recv_parse_data(struct s2n_connection *conn, union s2n_kex_server_data *kex_data);
int s2n_ecdhe_server_key_recv_parse_data(struct s2n_connection *conn, union s2n_kex_server_data *kex_data);
int s2n_rsa_server_key_recv_parse_data(struct s2n_connection *conn, union s2n_kex_server_data *kex_data);

/*
 * The below methods are used to perform the specific key exchange algorithm including writing data to the connection.
 * They are to be used by the server to handle sending the server's portion of the key exchange. They are not
 * responsible for signing the response or writing the signature to the connection.
 *
 * conn: in parameter which is the current connection
 * data_to_sign: out parameter that is the data required to be added to the signature hash to be used for signing
 */
int s2n_dhe_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign);
int s2n_ecdhe_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign);
int s2n_rsa_server_key_send(struct s2n_connection *conn, struct s2n_blob *data_to_sign);
