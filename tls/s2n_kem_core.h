/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_ecc.h"
#include "crypto/s2n_dhe.h"
#include "tls/s2n_connection.h"

#include <stdint.h>

/* Key exchange flags that can be OR'ed */
#define S2N_KEY_EXCHANGE_DH       0x01  /* Diffie-Hellman key exchange, including ephemeral */
#define S2N_KEY_EXCHANGE_EPH      0x02  /* Ephemeral key exchange */
#define S2N_KEY_EXCHANGE_ECC      0x04  /* Elliptic curve cryptography */

/* Structure that models a key agreement protocol and its specific operations */
struct s2n_kem_core {
    /* OR'ed S2N_KEY_EXCHANGE_* flags */
    uint16_t flags;

    int (*server_key_recv)(struct s2n_connection *conn, struct s2n_blob *data_to_sign);
    int (*server_key_send)(struct s2n_connection *conn, struct s2n_blob *data_to_sign);
    int (*client_key_recv)(struct s2n_connection *conn, struct s2n_blob *shared_key);
    int (*client_key_send)(struct s2n_connection *conn, struct s2n_blob *shared_key);
};

extern struct s2n_kem_core s2n_rsa;
extern struct s2n_kem_core s2n_dhe;
extern struct s2n_kem_core s2n_ecdhe;
