/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tests/s2n_test.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_server_key_exchange.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_kex_data.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

struct s2n_kex s2n_test_kem_kex = {
        .server_key_recv_read_data = &s2n_kem_server_key_recv_read_data,
        .server_key_recv_parse_data = &s2n_kem_server_key_recv_parse_data,
        .server_key_send = &s2n_kem_server_key_send,
        .client_key_recv = &s2n_kem_client_key_recv,
        .client_key_send = &s2n_kem_client_key_send,
};

struct s2n_cipher_suite s2n_test_suite = {
        .iana_value = { TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 },
        .key_exchange_alg = &s2n_test_kem_kex,
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    client_conn->secure.s2n_kem_keys.negotiated_kem = &s2n_sike_p503_r1;
    client_conn->secure.cipher_suite = &s2n_test_suite;

    server_conn->secure.s2n_kem_keys.negotiated_kem = &s2n_sike_p503_r1;
    server_conn->secure.cipher_suite = &s2n_test_suite;

    /* Part 1: Server calls send_key */
    struct s2n_blob data_to_sign = {0};
    EXPECT_SUCCESS(s2n_kem_server_key_send(server_conn, &data_to_sign));
    /* 2 extra bytes for the kem extension id and 2 additional bytes for the length of the public key sent over the wire. */
    const uint32_t KEM_PUBLIC_KEY_MESSAGE_SIZE = s2n_sike_p503_r1.public_key_length + 4;
    EXPECT_EQUAL(data_to_sign.size, KEM_PUBLIC_KEY_MESSAGE_SIZE);

    EXPECT_EQUAL(s2n_sike_p503_r1.private_key_length, server_conn->secure.s2n_kem_keys.private_key.size);
    struct s2n_blob server_key_message = {.size = KEM_PUBLIC_KEY_MESSAGE_SIZE, .data = s2n_stuffer_raw_read(&server_conn->handshake.io,
                                                                                                    KEM_PUBLIC_KEY_MESSAGE_SIZE)};
    EXPECT_NOT_NULL(server_key_message.data);

    /* Part 1.1: feed that to the client */
    EXPECT_SUCCESS(s2n_stuffer_write(&client_conn->handshake.io, &server_key_message));

    /* Part 2: Client calls recv_read and recv_parse */
    struct s2n_kex_raw_server_data raw_parms = {0};
    struct s2n_blob data_to_verify = {0};
    EXPECT_SUCCESS(s2n_kem_server_key_recv_read_data(client_conn, &data_to_verify, &raw_parms));
    EXPECT_EQUAL(data_to_verify.size, KEM_PUBLIC_KEY_MESSAGE_SIZE);
    EXPECT_SUCCESS(s2n_kem_server_key_recv_parse_data(client_conn, &raw_parms));
    EXPECT_EQUAL(s2n_sike_p503_r1.public_key_length, client_conn->secure.s2n_kem_keys.public_key.size);

    /* Part 3: Client calls send_key. The additional 2 bytes are for the ciphertext length sent over the wire */
    const uint32_t KEM_CIPHERTEXT_MESSAGE_SIZE = s2n_sike_p503_r1.ciphertext_length + 2;
    DEFER_CLEANUP(struct s2n_blob client_shared_key = {0}, s2n_free);
    EXPECT_SUCCESS(s2n_kem_client_key_send(client_conn, &client_shared_key));
    struct s2n_blob client_key_message = {.size = KEM_CIPHERTEXT_MESSAGE_SIZE, .data = s2n_stuffer_raw_read(&client_conn->handshake.io,
                                                                                                    KEM_CIPHERTEXT_MESSAGE_SIZE)};
    EXPECT_NOT_NULL(client_key_message.data);

    /* Part 3.1: Send that back to the server */
    EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_key_message));

    /* Part 4: Call client key recv */
    DEFER_CLEANUP(struct s2n_blob server_shared_key = {0}, s2n_free);
    EXPECT_SUCCESS(s2n_kem_client_key_recv(server_conn, &server_shared_key));
    EXPECT_BYTEARRAY_EQUAL(client_shared_key.data, server_shared_key.data, s2n_sike_p503_r1.shared_secret_key_length);

    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    END_TEST();
}
