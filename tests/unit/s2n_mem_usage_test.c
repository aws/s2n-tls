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

#ifdef __FreeBSD__
    /* FreeBSD requires POSIX compatibility off for its syscalls (enables __BSD_VISIBLE)
     * Without the below line, <sys/user.h> cannot be imported (it requires __BSD_VISIBLE) */
    #undef _POSIX_C_SOURCE
/* clang-format off */
    #include <sys/types.h>
    #include <sys/sysctl.h>
    /* clang-format on */
    #include <sys/user.h>
#elif defined(__OpenBSD__)
    #undef _POSIX_C_SOURCE
    #include <kvm.h>
/* clang-format off */
    #include <sys/types.h>
    #include <sys/sysctl.h>
    /* clang-format on */
    #include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

/* The number of connection pairs to allocate before measuring memory
 * usage. The greater the value, the more accurate the end result. */
#define MAX_CONNECTIONS 1000

ssize_t get_vm_data_size()
{
    long page_size = 0;
    ssize_t size = 0, resident = 0, share = 0, text = 0, lib = 0, data = 0, dt = 0;

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0) {
        return -1;
    }

    FILE *status_file = fopen("/proc/self/statm", "r");
    if (fscanf(status_file, "%zd %zd %zd %zd %zd %zd %zd", &size, &resident, &share, &text, &lib, &data, &dt) < 7) {
        fclose(status_file);
        return -1;
    }
    fclose(status_file);

    return data * page_size;
}

int main(int argc, char **argv)
{
    size_t connectionsToUse = MAX_CONNECTIONS;

    char *cert_chain = NULL;
    char *private_key = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    /* Skip the test unless specifically enabled.
     * This test is too unreliable to run in all customer environments.
     * We should choose specific, known builds to run this test in.
     */
    const char *env_var = getenv("S2N_EXPECTED_CONNECTION_MEMORY_KB");
    if (env_var == NULL) {
        END_TEST();
    }
    const int expected_kbs_per_conn = atoi(env_var);
    EXPECT_TRUE(expected_kbs_per_conn > 1);

    struct rlimit file_limit;
    EXPECT_SUCCESS(getrlimit(RLIMIT_NOFILE, &file_limit));
    /* 4 fds per connection: {client,server} {write,read} fd
     * and reserve 16 fds for libraries, stdin/stdout/stderr and so on */
    if (4 * connectionsToUse + 16 > file_limit.rlim_cur) {
        connectionsToUse = MAX(1, (file_limit.rlim_cur - 16) / 4);
    }

    struct s2n_connection **clients = calloc(connectionsToUse, sizeof(struct s2n_connection *));
    struct s2n_connection **servers = calloc(connectionsToUse, sizeof(struct s2n_connection *));

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

    struct s2n_config *client_config = NULL;
    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    struct s2n_config *server_config = NULL;
    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

    ssize_t vm_data_initial = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_initial, -1);

    /* Allocate all connections */
    for (size_t i = 0; i < connectionsToUse; i++) {
        struct s2n_connection *client_conn = NULL;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        clients[i] = client_conn;

        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        servers[i] = server_conn;
    }

    ssize_t vm_data_after_allocation = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_after_allocation, -1);

    for (size_t i = 0; i < connectionsToUse; i++) {
        EXPECT_SUCCESS(s2n_connections_set_io_pair(clients[i], servers[i], &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(servers[i], clients[i]));
    }

    ssize_t vm_data_after_handshakes = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_after_handshakes, -1);

    for (int i = 0; i < connectionsToUse; i++) {
        EXPECT_SUCCESS(s2n_connection_free_handshake(servers[i]));
        EXPECT_SUCCESS(s2n_connection_free_handshake(clients[i]));
    }
    ssize_t vm_data_after_free_handshake = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_after_free_handshake, -1);

    for (int i = 0; i < connectionsToUse; i++) {
        EXPECT_SUCCESS(s2n_connection_release_buffers(servers[i]));
        EXPECT_SUCCESS(s2n_connection_release_buffers(clients[i]));
    }
    ssize_t vm_data_after_release_buffers = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_after_release_buffers, -1);

    for (int i = 0; i < connectionsToUse; i++) {
        EXPECT_SUCCESS(s2n_connection_free(clients[i]));
        EXPECT_SUCCESS(s2n_connection_free(servers[i]));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_config_free(client_config));

    free(cert_chain);
    free(private_key);
    free(clients);
    free(servers);

    EXPECT_TRUE(vm_data_after_free_handshake <= vm_data_after_handshakes);
    EXPECT_TRUE(vm_data_after_release_buffers <= vm_data_after_free_handshake);

    ssize_t handshake_diff = (vm_data_after_handshakes - vm_data_initial);
    ssize_t allocation_diff = (vm_data_after_allocation - vm_data_initial);
    EXPECT_TRUE(allocation_diff <= handshake_diff);

    ssize_t mem_per_conn = handshake_diff / (connectionsToUse * 2);
    ssize_t kbs_per_conn = mem_per_conn / 1024;

    if (kbs_per_conn != expected_kbs_per_conn) {
        printf("\nExpected KB per connection: %i\n", expected_kbs_per_conn);
        printf("\nActual KB per connection: %li\n", kbs_per_conn);
        printf("This is a %.2f%% change\n",
                (kbs_per_conn - expected_kbs_per_conn) * 100.0 / expected_kbs_per_conn);

        printf("\n");
        printf("VmData initial:              %10zd\n", vm_data_initial);
        printf("VmData after allocations:    %10zd\n", vm_data_after_allocation);
        printf("VmData after handshakes:     %10zd\n", vm_data_after_handshakes);
        printf("VmData after free handshake: %10zd\n", vm_data_after_free_handshake);
        printf("VmData after release:        %10zd\n", vm_data_after_release_buffers);
        printf("Number of connections used:  %10zu\n", connectionsToUse);
        FAIL_MSG("Unexpected memory usage. If expected, update MEM_PER_CONNECTION.");
    }

    END_TEST();
}
