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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <fcntl.h>
#include <errno.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"
#include "utils/s2n_safety.h"

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

int main(int argc, char **argv)
{
    struct s2n_config *server_config;
    struct s2n_config *client_config;
    struct s2n_connection *server_conn;
    struct s2n_connection *client_conn;
    int server_to_client[2];
    int client_to_server[2];
    char *cert_chain;
    char *private_key;

    BEGIN_TEST();

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));
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
        
    /* Create config with s2n_config_add_cert_chain_and_key_to_store API */
    {
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
       
        EXPECT_NOT_NULL(server_conn = create_conn(S2N_SERVER, server_config, server_to_client, client_to_server));
        EXPECT_NOT_NULL(client_conn = create_conn(S2N_CLIENT, client_config, server_to_client, client_to_server));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn->handshake.handshake_type));
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
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
    END_TEST();
    return 0;
}
