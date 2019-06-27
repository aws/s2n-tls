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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <fcntl.h>
#include <errno.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"
#include "utils/s2n_safety.h"

#define NUM_TIED_CERTS 100

struct s2n_connection *create_conn(s2n_mode mode, struct s2n_config *config, int s_to_c[], int c_to_s[]) {
    struct s2n_connection *conn = s2n_connection_new(mode);
    GUARD_PTR(s2n_connection_set_config(conn, config));
    
    if (mode == S2N_SERVER) {
        GUARD_PTR(s2n_connection_set_read_fd(conn, c_to_s[0]));
        GUARD_PTR(s2n_connection_set_write_fd(conn, s_to_c[1]));
    } else {
        GUARD_PTR(s2n_connection_set_read_fd(conn, s_to_c[0]));
        GUARD_PTR(s2n_connection_set_write_fd(conn, c_to_s[1]));
    }

    return conn;
}

static int num_times_cb_executed = 0;
static struct s2n_cert_chain_and_key *test_cert_tiebreak_cb(struct s2n_cert_chain_and_key *cert1,
        struct s2n_cert_chain_and_key *cert2,
        uint8_t *name,
        uint32_t name_len)
{
    const int priority1 = *((int *) s2n_cert_chain_and_key_get_ctx(cert1));
    const int priority2 = *((int *) s2n_cert_chain_and_key_get_ctx(cert2));
    num_times_cb_executed++;
    return (priority1 > priority2 ? cert1 : cert2);
}

int main(int argc, char **argv)
{
    struct s2n_config *server_config;
    struct s2n_config *client_config;
    struct s2n_connection *server_conn;
    struct s2n_connection *client_conn;
    int server_to_client[2];
    int client_to_server[2];
    char *alligator_cert;
    char *alligator_key;
    char *cert_chain;
    char *private_key;

    BEGIN_TEST();

    EXPECT_NOT_NULL(alligator_cert = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(alligator_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ALLIGATOR_SAN_CERT, alligator_cert, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ALLIGATOR_SAN_KEY, alligator_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Create nonblocking pipes */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));
    for (int i = 0; i < 2; i++) {
       EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
       EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
    }

    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
    /* Create config with s2n_config_add_cert_chain_and_key_to_store API with multiple certs */
    {
        struct s2n_cert_chain_and_key *default_cert;
        /* Associated data to attach to each certificate to use in the tiebreak callback. */
        int tiebreak_priorites[NUM_TIED_CERTS] = { 0 };
        /* Collection of certs with the same domain name that need to have ties resolved. */
        struct s2n_cert_chain_and_key *tied_certs[NUM_TIED_CERTS] = { NULL };
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cert_tiebreak_callback(server_config, test_cert_tiebreak_cb));

        /* Need to add at least one cert with a different domain name to make cert lookup utilize hashmap */
        EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));

        /* Add NUM_TIED_CERTS that are actually the same certificate(www.alligator.com) to trigger the tiebreak callback. */
        for (unsigned int i = 0; i < NUM_TIED_CERTS; i++) {
            EXPECT_NOT_NULL(tied_certs[i] = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tied_certs[i], alligator_cert, alligator_key));
            tiebreak_priorites[i] = i;
            EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ctx(tied_certs[i], (void*) &tiebreak_priorites[i]));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tied_certs[i]));
        }

        EXPECT_NOT_NULL(server_conn = create_conn(S2N_SERVER, server_config, server_to_client, client_to_server));
        EXPECT_NOT_NULL(client_conn = create_conn(S2N_CLIENT, client_config, server_to_client, client_to_server));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "www.alligator.com"));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn->handshake.handshake_type));
        EXPECT_EQUAL(num_times_cb_executed, NUM_TIED_CERTS - 1);
        struct s2n_cert_chain_and_key *selected_cert = s2n_connection_get_selected_cert(server_conn);
        /* The last alligator certificate should have the highest priority */
        EXPECT_EQUAL(selected_cert, tied_certs[(NUM_TIED_CERTS - 1)]);
        EXPECT_EQUAL(s2n_cert_chain_and_key_get_ctx(selected_cert), (void*) &tiebreak_priorites[(NUM_TIED_CERTS - 1)]);
        EXPECT_EQUAL(*((int *) s2n_cert_chain_and_key_get_ctx(selected_cert)), NUM_TIED_CERTS - 1);
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        for (int i = 0; i < NUM_TIED_CERTS; i++) {
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tied_certs[i]));
        }
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(default_cert));
        EXPECT_SUCCESS(s2n_config_free(server_config));
    }

    /* Create config with deprecated s2n_config_add_cert_chain_and_key API */
    {
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));

        EXPECT_NOT_NULL(server_conn = create_conn(S2N_SERVER, server_config, server_to_client, client_to_server));
        EXPECT_NOT_NULL(client_conn = create_conn(S2N_CLIENT, client_config, server_to_client, client_to_server));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn->handshake.handshake_type));
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(server_config));
    }

    for (int i = 0; i < 2; i++) {
       EXPECT_SUCCESS(close(server_to_client[i]));
       EXPECT_SUCCESS(close(client_to_server[i]));
    }

    EXPECT_SUCCESS(s2n_config_free(client_config));

    free(cert_chain);
    free(private_key);
    free(alligator_cert);
    free(alligator_key);
    END_TEST();
    return 0;
}
