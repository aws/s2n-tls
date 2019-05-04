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

#define KEM_ID 0xabcd
#define TEST_PUBLIC_KEY_LENGTH 0x0002
const uint8_t TEST_PUBLIC_KEY[] = {0x02, 0x02};

#define TEST_PRIVATE_KEY_LENGTH 3
const uint8_t TEST_PRIVATE_KEY[] = {0x03, 0x03, 0x03};

#define TEST_SHARED_SECRET_LENGTH 4
const uint8_t TEST_SHARED_SECRET[] = {0x04, 0x04, 0x04, 0x04};

#define TEST_CIPHERTEXT_LENGTH 0x0005
const uint8_t TEST_CIPHERTEXT[] = {0x05, 0x05, 0x05, 0x05, 0x05};

const int TEST_SERVER_SEND_KEY_MESSAGE_LENGTH = sizeof(kem_extension_size) + sizeof(kem_public_key_size) + TEST_PUBLIC_KEY_LENGTH;
const uint8_t TEST_SERVER_SEND_KEY_MESSAGE[] = {0xab, 0xcd, 0x00, 0x02, 0x02, 0x02};

const int TEST_CLIENT_SEND_KEY_MESSAGE_LENGTH = sizeof(kem_ciphertext_key_size) + TEST_CIPHERTEXT_LENGTH;
const uint8_t TEST_CLIENT_SEND_KEY_MESSAGE[] = {0x00, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};


int s2n_test_generate_keypair(unsigned char *public_key, unsigned char *private_key)
{
    memset(public_key, TEST_PUBLIC_KEY_LENGTH, TEST_PUBLIC_KEY_LENGTH);
    memset(private_key, TEST_PRIVATE_KEY_LENGTH, TEST_PRIVATE_KEY_LENGTH);
    return 0;
}
int s2n_test_encrypt(unsigned char *ciphertext, unsigned char *shared_secret, const unsigned char *public_key)
{
    GUARD(memcmp(public_key, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH));
    memset(ciphertext, TEST_CIPHERTEXT_LENGTH, TEST_CIPHERTEXT_LENGTH);
    memset(shared_secret, TEST_SHARED_SECRET_LENGTH, TEST_SHARED_SECRET_LENGTH);
    return 0;
}
int s2n_test_decrypt(unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key)
{
    GUARD(memcmp(ciphertext, TEST_CIPHERTEXT, TEST_CIPHERTEXT_LENGTH));
    GUARD(memcmp(private_key, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH));
    memset(shared_secret, TEST_SHARED_SECRET_LENGTH, TEST_SHARED_SECRET_LENGTH);
    return 0;
}

struct s2n_kem s2n_test_kem = {
        .kem_extension_id = KEM_ID,
        .public_key_length = TEST_PUBLIC_KEY_LENGTH,
        .private_key_length = TEST_PRIVATE_KEY_LENGTH,
        .shared_secret_key_length = TEST_SHARED_SECRET_LENGTH,
        .ciphertext_length = TEST_CIPHERTEXT_LENGTH,
        .generate_keypair = &s2n_test_generate_keypair,
        .encapsulate = &s2n_test_encrypt,
        .decapsulate = &s2n_test_decrypt,
};

struct s2n_kex s2n_test_kem_kex = {
        .server_key_recv_read_data = &s2n_kem_server_key_recv_read_data,
        .server_key_recv_parse_data = &s2n_kem_server_key_recv_parse_data,
        .server_key_send = &s2n_kem_server_key_send,
        .client_key_recv = &s2n_kem_client_key_recv,
        .client_key_send = &s2n_kem_client_key_send,
};

struct s2n_cipher_suite s2n_test_suite = {
        .key_exchange_alg = &s2n_test_kem_kex,
};

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    client_conn->secure.s2n_kem_keys.negotiated_kem = &s2n_test_kem;
    client_conn->secure.cipher_suite = &s2n_test_suite;

    server_conn->secure.s2n_kem_keys.negotiated_kem = &s2n_test_kem;
    server_conn->secure.cipher_suite = &s2n_test_suite;

    /* Part 1: Server calls send_key */
    struct s2n_blob data_to_sign = {0};
    EXPECT_SUCCESS(s2n_kem_server_key_send(server_conn, &data_to_sign));
    EXPECT_EQUAL(data_to_sign.size, TEST_SERVER_SEND_KEY_MESSAGE_LENGTH);

    EXPECT_EQUAL(TEST_PRIVATE_KEY_LENGTH, server_conn->secure.s2n_kem_keys.private_key.size);
    EXPECT_BYTEARRAY_EQUAL(TEST_PRIVATE_KEY, server_conn->secure.s2n_kem_keys.private_key.data, TEST_PRIVATE_KEY_LENGTH);
    struct s2n_blob server_key_message = {.size = TEST_SERVER_SEND_KEY_MESSAGE_LENGTH, .data = s2n_stuffer_raw_read(&server_conn->handshake.io, TEST_SERVER_SEND_KEY_MESSAGE_LENGTH)};
    EXPECT_BYTEARRAY_EQUAL(TEST_SERVER_SEND_KEY_MESSAGE, server_key_message.data, TEST_SERVER_SEND_KEY_MESSAGE_LENGTH);

    /* Part 1.1: feed that to the client */
    s2n_stuffer_write(&client_conn->handshake.io, &server_key_message);

    /* Part 2: Client calls recv_read and recv_parse */
    struct s2n_kex_raw_server_data raw_parms = {{{0}}};
    struct s2n_blob data_to_verify = {0};
    EXPECT_SUCCESS(s2n_kem_server_key_recv_read_data(client_conn, &data_to_verify, &raw_parms));
    EXPECT_EQUAL(data_to_verify.size, TEST_SERVER_SEND_KEY_MESSAGE_LENGTH);
    EXPECT_SUCCESS(s2n_kem_server_key_recv_parse_data(client_conn, &raw_parms));
    EXPECT_EQUAL(TEST_PUBLIC_KEY_LENGTH, client_conn->secure.s2n_kem_keys.public_key.size);
    EXPECT_BYTEARRAY_EQUAL(TEST_PUBLIC_KEY, client_conn->secure.s2n_kem_keys.public_key.data, TEST_PUBLIC_KEY_LENGTH);

    /* Part 3: Client calls send_key */
    DEFER_CLEANUP(struct s2n_blob client_shared_key = {0}, s2n_free);
    EXPECT_SUCCESS(s2n_kem_client_key_send(client_conn, &client_shared_key));
    EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, client_shared_key.data, TEST_SHARED_SECRET_LENGTH);
    struct s2n_blob client_key_message = {.size = TEST_CLIENT_SEND_KEY_MESSAGE_LENGTH, .data = s2n_stuffer_raw_read(&client_conn->handshake.io, TEST_CLIENT_SEND_KEY_MESSAGE_LENGTH)};
    EXPECT_BYTEARRAY_EQUAL(TEST_CLIENT_SEND_KEY_MESSAGE, client_key_message.data, TEST_CLIENT_SEND_KEY_MESSAGE_LENGTH);

    /* Part 3.1: Send that back to the server */
    EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &client_key_message));

    /* Part 4: Call client key recv */
    DEFER_CLEANUP(struct s2n_blob server_shared_key = {0}, s2n_free);
    EXPECT_SUCCESS(s2n_kem_client_key_recv(server_conn, &server_shared_key));
    EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, server_shared_key.data, TEST_SHARED_SECRET_LENGTH);

    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    END_TEST();
}
