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
#include "utils/s2n_blob.h"

/*
 * The below methods are used to perform the specific key exchange algorithm including reading data from the connection.
 * They are to be used by the client to handle sending the client's portion of the key exchange data. They are not
 * responsible for verifying the response or reading the signature from the connection.
 *
 * conn: in parameter which is the current connection
 * data_to_verify: out parameter that is the data required to be added to the signature hash to be used for verifying
 * the data
 */
int s2n_dhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key);
int s2n_ecdhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key);
int s2n_rsa_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key);

/*
 * The below methods are used to perform the specific key exchange algorithm including writing data to the connection.
 * They are to be used by the server to handle receiving the client's portion of the key exchange data. They are not
 * responsible for signing the response or writing the signature to the connection.
 *
 * conn: in parameter which is the current connection
 * data_to_sign: out parameter that is the data required to be added to the signature hash to be used for signing
 */
int s2n_dhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key);
int s2n_ecdhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key);
int s2n_rsa_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key);
