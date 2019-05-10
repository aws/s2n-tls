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

#include "crypto/s2n_crypto.h"
#include "crypto/s2n_drbg.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"

#include "stuffer/s2n_stuffer.h"

#include "tests/s2n_test.h"

#include "tests/testlib/s2n_testlib.h"

#include "tests/unit/s2n_nist_kats.h"

#include "tls/s2n_kex.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_cipher_suites.h"

#define SERVER_KEY_MESSAGE_LENGTH 711
#define CLIENT_KEY_MESSAGE_LENGTH 470

/* If the configured lib crypto supports a custom random number generator this test is run with a AES 256 DRBG with no
 * prediction resistance RNG. Running in that mode all the server and client key exchange messages and final master
 * secret can be checked against the expected values in RSP_FILE_NAME. */
#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
#define RSP_FILE_NAME "kats/hybrid_ecdhe_sike_p503.kat"

struct s2n_blob kat_entropy_blob = {0};
int s2n_entropy_generator(struct s2n_blob *blob)
{
    eq_check(blob->size, kat_entropy_blob.size);
    blob->data = kat_entropy_blob.data;
    return 0;
}
#endif

int setup_connection(struct s2n_connection *conn) {
    conn->actual_protocol_version = S2N_TLS12;
    conn->secure.server_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];
    conn->secure.s2n_kem_keys.negotiated_kem = &s2n_sike_supported_params[0];
    conn->secure.cipher_suite = &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384;
    conn->secure.conn_hash_alg = S2N_HASH_SHA384;
    return 0;
}

int main(int argc, char **argv) {
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Read the seed from the RSP_FILE and create the DRBG for the test. Since the seed is the same (and prediction
     * resistance is off) all calls to generate random data will return the same sequence. Thus the server always
     * generates the same ECDHE point and KEM public key, the client does the same. */
    FILE *kat_file = fopen(RSP_FILE_NAME, "r");
    EXPECT_NOT_NULL(kat_file);
    EXPECT_SUCCESS(s2n_alloc(&kat_entropy_blob, 48));
    EXPECT_SUCCESS(ReadHex(kat_file, kat_entropy_blob.data, 48, "seed = "));

    struct s2n_drbg drbg = {.entropy_generator = &s2n_entropy_generator};
    s2n_stack_blob(personalization_string, 32, 32);
    EXPECT_SUCCESS(s2n_drbg_instantiate(&drbg, &personalization_string, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
    EXPECT_SUCCESS(s2n_set_private_drbg_for_test(drbg));
#endif

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    /* Part 1 setup a client and server connection with everything they need for a key exchange */
    struct s2n_connection *client_conn, *server_conn;
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    struct s2n_config *server_config, *client_config;

    client_config = s2n_fetch_unsafe_client_testing_config();
    GUARD(s2n_connection_set_config(client_conn, client_config));

    /* Part 1.1 setup server's keypair and the give the client the certificate */
    char *cert_chain;
    char *private_key;
    char *client_chain;
    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(client_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_LEAF_CERT, client_chain, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
    GUARD(s2n_set_signature_hash_pair_from_preference_list(server_conn, &server_conn->handshake_params.client_sig_hash_algs, &server_conn->secure.conn_hash_alg, &server_conn->secure.conn_sig_alg));

    DEFER_CLEANUP(struct s2n_stuffer certificate_in = {{0}}, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_stuffer certificate_out = {{0}}, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_blob temp_blob;
    temp_blob.data = (uint8_t *) client_chain;
    temp_blob.size = strlen(client_chain) + 1;
    EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &temp_blob));
    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

    temp_blob.size = s2n_stuffer_data_available(&certificate_out);
    temp_blob.data = s2n_stuffer_raw_read(&certificate_out, temp_blob.size);
    s2n_cert_type cert_type;
    EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &cert_type, &temp_blob));

    server_conn->handshake_params.our_chain_and_key = chain_and_key;

    EXPECT_SUCCESS(setup_connection(server_conn));
    EXPECT_SUCCESS(setup_connection(client_conn));

    /* Part 2 server sends key first */
    EXPECT_SUCCESS(s2n_server_key_send(server_conn));

    /* Part 2.1 verify the results as best we can */
    EXPECT_EQUAL(server_conn->handshake.io.write_cursor, SERVER_KEY_MESSAGE_LENGTH);
    struct s2n_blob server_key_message = {.size = SERVER_KEY_MESSAGE_LENGTH, .data = s2n_stuffer_raw_read(&server_conn->handshake.io, SERVER_KEY_MESSAGE_LENGTH)};

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Part 2.1.1 if we're running in known answer mode check the server's key exchange message matches the expected value */
    uint8_t expected_server_key_message[SERVER_KEY_MESSAGE_LENGTH];
    EXPECT_SUCCESS(ReadHex(kat_file, expected_server_key_message, SERVER_KEY_MESSAGE_LENGTH, "expected_server_key_exchange = "));
    EXPECT_BYTEARRAY_EQUAL(expected_server_key_message, server_key_message.data, SERVER_KEY_MESSAGE_LENGTH);
#endif

    /* Part 2.2 copy server's message to the client's stuffer */
    s2n_stuffer_write(&client_conn->handshake.io, &server_key_message);

    /* Part 3 client recvs the server's key and sends the client key exchange message */
    EXPECT_SUCCESS(s2n_server_key_recv(client_conn));
    EXPECT_SUCCESS(s2n_client_key_send(client_conn));

    /* Part 3.1 verify the results as best we can */
    EXPECT_EQUAL(client_conn->handshake.io.write_cursor - client_conn->handshake.io.read_cursor, CLIENT_KEY_MESSAGE_LENGTH);
    struct s2n_blob client_key_message = {.size = CLIENT_KEY_MESSAGE_LENGTH, .data = s2n_stuffer_raw_read(&client_conn->handshake.io, CLIENT_KEY_MESSAGE_LENGTH)};


#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Part 3.1.1 if we're running in known answer mode check the client's key exchange message matches the expected value */
    uint8_t expected_client_key_message[CLIENT_KEY_MESSAGE_LENGTH];
    EXPECT_SUCCESS(ReadHex(kat_file, expected_client_key_message, CLIENT_KEY_MESSAGE_LENGTH, "expected_client_key_exchange = "));
    EXPECT_BYTEARRAY_EQUAL(expected_client_key_message, client_key_message.data, CLIENT_KEY_MESSAGE_LENGTH);
#endif

    /* Part 3.2 copy the client's message back to the server's stuffer */
    s2n_stuffer_write(&server_conn->handshake.io, &client_key_message);

    /* Part 4 server receives the client's message */
    EXPECT_SUCCESS(s2n_client_key_recv(server_conn));

    /* Part 4.1 verify results as best we can, the client and server should at least have the same master secret */
    EXPECT_BYTEARRAY_EQUAL(server_conn->secure.master_secret, client_conn->secure.master_secret, S2N_TLS_SECRET_LEN);

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Part 4.1.1 if we're running in known answer mode check that both the client and server got the expected master secret
     * from the RSP_FILE */
    uint8_t expected_master_secret[S2N_TLS_SECRET_LEN];
    EXPECT_SUCCESS(ReadHex(kat_file, expected_master_secret, S2N_TLS_SECRET_LEN, "expected_master_secret = "));
    EXPECT_BYTEARRAY_EQUAL(expected_master_secret, client_conn->secure.master_secret, S2N_TLS_SECRET_LEN);
    EXPECT_BYTEARRAY_EQUAL(expected_master_secret, server_conn->secure.master_secret, S2N_TLS_SECRET_LEN);
#endif

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    free(cert_chain);
    free(client_chain);
    free(private_key);

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Extra cleanup needed for the known answer test */
    fclose(kat_file);
#endif

    END_TEST();
}

