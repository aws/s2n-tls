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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    /* We need to execute s2n_init before the seccomp filter is applied.
     * Some one-time initialization involves opening files, like "dev/urandom".
     * If built with aws-lc, s2n-tls also needs to call CRYPTO_pre_sandbox_init()
     * before seccomp starts sandboxing.
     *
     * An application using s2n-tls with seccomp would need to do the same.
     */
    BEGIN_TEST();

    /* One of the primary purposes of seccomp is to block opening new files.
     * So before we enable seccomp, we need to open any files that the test would
     * need. In this case, we need to load certificate pems from files.
     *
     * An application using s2n-tls with seccomp would need to do the same.
     */
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
            cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY,
            private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    /* No unexpected syscalls allowed beyond this point */
    EXPECT_OK(s2n_seccomp_init());

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(config, cert_chain_pem));

    const char *security_policies[] = { "test_all_tls12", "default_tls13" };

    for (size_t i = 0; i < s2n_array_len(security_policies); i++) {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, security_policies[i]));
        EXPECT_SUCCESS(s2n_set_server_name(client, "127.0.0.1"));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, security_policies[i]));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        const uint8_t data[] = "hello world";
        uint8_t buffer[100] = { 0 };
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(client, data, sizeof(data), &blocked), sizeof(data));
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(data));
        EXPECT_BYTEARRAY_EQUAL(buffer, data, sizeof(data));
    }

    END_TEST();
}
