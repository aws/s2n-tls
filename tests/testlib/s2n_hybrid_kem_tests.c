/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_kem.h"
#include "tests/testlib/s2n_nist_kats.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_drbg.h"
#include "crypto/s2n_openssl.h"
#include "stuffer/s2n_stuffer.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_cipher_suites.h"

/* If the configured lib crypto supports a custom random number generator this test is run with a AES 256 DRBG with no
 * prediction resistance RNG. Running in that mode all the server and client key exchange messages and final master
 * secret can be checked against the expected values in RSP_FILE_NAME. */
#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
struct s2n_blob hybrid_kat_entropy_blob = {0};
int s2n_entropy_generator(struct s2n_blob *blob)
{
    eq_check(blob->size, hybrid_kat_entropy_blob.size);
    blob->data = hybrid_kat_entropy_blob.data;
    return 0;
}
#endif

int setup_connection(struct s2n_connection *conn, const struct s2n_kem *kem, struct s2n_cipher_suite *cipher_suite) {
    conn->actual_protocol_version = S2N_TLS12;
    conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
    conn->secure.s2n_kem_keys.negotiated_kem = kem;
    conn->secure.cipher_suite = cipher_suite;
    conn->secure.conn_sig_scheme = s2n_rsa_pkcs1_sha384;
    return 0;
}

int s2n_test_hybrid_ecdhe_kem_with_kat(const struct s2n_kem *kem, struct s2n_cipher_suite *cipher_suite,
        const char * kat_file_name, uint32_t server_key_message_length, uint32_t client_key_message_length) {
    /* Part 1 setup a client and server connection with everything they need for a key exchange */
    struct s2n_connection *client_conn, *server_conn;
    GUARD_NONNULL(client_conn = s2n_connection_new(S2N_CLIENT));
    GUARD_NONNULL(server_conn = s2n_connection_new(S2N_SERVER));

    struct s2n_config *server_config, *client_config;

    client_config = s2n_fetch_unsafe_client_testing_config();
    GUARD(s2n_connection_set_config(client_conn, client_config));

    /* Part 1.1 setup server's keypair and the give the client the certificate */
    char *cert_chain;
    char *private_key;
    char *client_chain;
    GUARD_NONNULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD_NONNULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD_NONNULL(client_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD_NONNULL(server_config = s2n_config_new());
    GUARD(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_RSA_2048_PKCS1_LEAF_CERT, client_chain, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *chain_and_key;
    GUARD_NONNULL(chain_and_key = s2n_cert_chain_and_key_new());
    GUARD(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    GUARD(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    GUARD(s2n_connection_set_config(server_conn, server_config));

    GUARD(s2n_choose_sig_scheme_from_peer_preference_list(server_conn, &server_conn->handshake_params.client_sig_hash_algs, &server_conn->secure.conn_sig_scheme));

    DEFER_CLEANUP(struct s2n_stuffer certificate_in = {0}, s2n_stuffer_free);
    GUARD(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_stuffer certificate_out = {0}, s2n_stuffer_free);
    GUARD(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_blob temp_blob;
    temp_blob.data = (uint8_t *) client_chain;
    temp_blob.size = strlen(client_chain) + 1;
    GUARD(s2n_stuffer_write(&certificate_in, &temp_blob));
    GUARD(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

    temp_blob.size = s2n_stuffer_data_available(&certificate_out);
    temp_blob.data = s2n_stuffer_raw_read(&certificate_out, temp_blob.size);
    s2n_pkey_type pkey_type;
    GUARD(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &pkey_type, &temp_blob));

    server_conn->handshake_params.our_chain_and_key = chain_and_key;

    GUARD(setup_connection(server_conn, kem, cipher_suite));
    GUARD(setup_connection(client_conn, kem, cipher_suite));

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Read the seed from the RSP_FILE and create the DRBG for the test. Since the seed is the same (and prediction
     * resistance is off) all calls to generate random data will return the same sequence. Thus the server always
     * generates the same ECDHE point and KEM public key, the client does the same. */
    FILE *kat_file = fopen(kat_file_name, "r");
    GUARD_NONNULL(kat_file);
    GUARD(s2n_alloc(&hybrid_kat_entropy_blob, 48));
    GUARD(ReadHex(kat_file, hybrid_kat_entropy_blob.data, 48, "seed = "));

    struct s2n_drbg drbg = {.entropy_generator = &s2n_entropy_generator};
    s2n_stack_blob(personalization_string, 32, 32);
    GUARD(s2n_drbg_instantiate(&drbg, &personalization_string, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
    GUARD(s2n_set_private_drbg_for_test(drbg));
#endif

    /* Part 2 server sends key first */
    GUARD(s2n_server_key_send(server_conn));

    /* Part 2.1 verify the results as best we can */
    eq_check(server_conn->handshake.io.write_cursor, server_key_message_length);
    struct s2n_blob server_key_message = {.size = server_key_message_length, .data = s2n_stuffer_raw_read(&server_conn->handshake.io, server_key_message_length)};

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Part 2.1.1 if we're running in known answer mode check the server's key exchange message matches the expected value */
    uint8_t *expected_server_key_message;
    GUARD_NONNULL(expected_server_key_message = malloc(server_key_message_length));
    GUARD(ReadHex(kat_file, expected_server_key_message, server_key_message_length, "expected_server_key_exchange = "));

    /* Compare byte arrays for equality */
    eq_check(memcmp(expected_server_key_message, server_key_message.data, server_key_message_length), 0);
#endif

    /* Part 2.2 copy server's message to the client's stuffer */
    s2n_stuffer_write(&client_conn->handshake.io, &server_key_message);

    /* Part 3 client recvs the server's key and sends the client key exchange message */
    GUARD(s2n_server_key_recv(client_conn));
    GUARD(s2n_client_key_send(client_conn));

    /* Part 3.1 verify the results as best we can */
    eq_check(client_conn->handshake.io.write_cursor - client_conn->handshake.io.read_cursor, client_key_message_length);
    struct s2n_blob client_key_message = {.size = client_key_message_length, .data = s2n_stuffer_raw_read(&client_conn->handshake.io, client_key_message_length)};


#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Part 3.1.1 if we're running in known answer mode check the client's key exchange message matches the expected value */
    uint8_t *expected_client_key_message;
    GUARD_NONNULL(expected_client_key_message = malloc(client_key_message_length));
    GUARD(ReadHex(kat_file, expected_client_key_message, client_key_message_length, "expected_client_key_exchange = "));

    /* Compare byte arrays for equality */
    eq_check(memcmp(expected_client_key_message, client_key_message.data, client_key_message_length), 0);
#endif

    /* Part 3.2 copy the client's message back to the server's stuffer */
    s2n_stuffer_write(&server_conn->handshake.io, &client_key_message);

    /* Part 4 server receives the client's message */
    GUARD(s2n_client_key_recv(server_conn));

    /* Part 4.1 verify results as best we can, the client and server should at least have the same master secret */
    /* Compare byte arrays for equality */
    eq_check(memcmp(server_conn->secure.master_secret, client_conn->secure.master_secret, S2N_TLS_SECRET_LEN), 0);

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Part 4.1.1 if we're running in known answer mode check that both the client and server got the expected master secret
     * from the RSP_FILE */
    uint8_t expected_master_secret[S2N_TLS_SECRET_LEN];
    GUARD(ReadHex(kat_file, expected_master_secret, S2N_TLS_SECRET_LEN, "expected_master_secret = "));
    /* Compare byte arrays for equality */
    eq_check(memcmp(expected_master_secret, client_conn->secure.master_secret, S2N_TLS_SECRET_LEN), 0);
    eq_check(memcmp(expected_master_secret, server_conn->secure.master_secret, S2N_TLS_SECRET_LEN), 0);
#endif

    GUARD(s2n_cert_chain_and_key_free(chain_and_key));
    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_connection_free(server_conn));
    GUARD(s2n_config_free(server_config));
    free(cert_chain);
    free(client_chain);
    free(private_key);

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Extra cleanup needed for the known answer test */
    fclose(kat_file);
    free(expected_server_key_message);
    free(expected_client_key_message);
#endif

    return 0;
}
