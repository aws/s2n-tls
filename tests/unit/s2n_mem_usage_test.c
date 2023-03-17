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

/* This is roughly the current memory usage per connection, in KB */
#ifdef __FreeBSD__
    #define MEM_PER_CONNECTION 57
#elif defined(__OpenBSD__)
    #define MEM_PER_CONNECTION 60
#else
    #define MEM_PER_CONNECTION 49
#endif

/* This is the maximum memory per connection including 4KB of slack */
#define TEST_SLACK 4
#define MAX_MEM_PER_CONNECTION \
    ((MEM_PER_CONNECTION + TEST_SLACK) * 1024)

/* This is the total maximum memory allowed */
#define MAX_MEM_ALLOWED(num_connections) \
    (2 * (num_connections) *MAX_MEM_PER_CONNECTION)

/* This is the correct value of MEM_PER_CONNECTION based on test results.
 * Basically, this calculation should reverse MAX_MEM_ALLOWED */
#define ACTUAL_MEM_PER_CONNECTION(num_connections, max_mem) \
    ((((max_mem) / 2 / (num_connections)) / 1024) - TEST_SLACK)

ssize_t get_vm_data_size()
{
#ifdef __linux__
    long page_size;
    ssize_t size, resident, share, text, lib, data, dt;

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

#elif defined(__FreeBSD__)
    pid_t ppid = getpid();
    int pidinfo[4];
    pidinfo[0] = CTL_KERN;
    pidinfo[1] = KERN_PROC;
    pidinfo[2] = KERN_PROC_PID;
    pidinfo[3] = (int) ppid;

    struct kinfo_proc procinfo = { 0 };

    size_t len = sizeof(procinfo);

    sysctl(pidinfo, nitems(pidinfo), &procinfo, &len, NULL, 0);

    /* Taken from linprocfs implementation
     * https://github.com/freebsd/freebsd-src/blob/779fd05344662aeec79c29470258bf657318eab3/sys/compat/linprocfs/linprocfs.c#L1019 */
    segsz_t lsize = (procinfo.ki_size >> PAGE_SHIFT) - procinfo.ki_dsize - procinfo.ki_ssize - procinfo.ki_tsize - 1;

    return lsize << PAGE_SHIFT;

#elif defined(__OpenBSD__)
    struct kinfo_proc *procinfo;
    kvm_t *kd;
    pid_t ppid;
    long page_size;
    ssize_t size;
    int nentries;

    kd = kvm_open(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    ppid = getpid();
    procinfo = kvm_getprocs(kd, KERN_PROC_PID, ppid, sizeof(*procinfo), &nentries);
    if (procinfo == NULL || nentries == 0) {
        return -1;
    }

    /* Taken from ps(1)'s calculation of vsize
     * https://github.com/openbsd/src/blob/329e3480337617df4d195c9a400c3f186254b137/bin/ps/print.c#L603 */
    size = procinfo->p_vm_dsize + procinfo->p_vm_ssize + procinfo->p_vm_tsize;

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0) {
        return -1;
    }
    kvm_close(kd);

    return (size * page_size);
#else
    /* Not implemented for other platforms */
    return 0;
#endif
}

int main(int argc, char **argv)
{
    size_t connectionsToUse = MAX_CONNECTIONS;

    char *cert_chain;
    char *private_key;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    /* Skip the test when running under valgrind or address sanitizer, as those tools
     * impact the memory usage. */
    if (getenv("S2N_VALGRIND") != NULL || getenv("S2N_ADDRESS_SANITIZER") != NULL) {
        END_TEST();
    }

    struct rlimit file_limit;
    EXPECT_SUCCESS(getrlimit(RLIMIT_NOFILE, &file_limit));
    /* 4 fds per connection: {client,server} {write,read} fd
     * and reserve 16 fds for libraries, stdin/stdout/stderr and so on */
    if (4 * connectionsToUse + 16 > file_limit.rlim_cur) {
        connectionsToUse = MAX(1, (file_limit.rlim_cur - 16) / 4);
    }

    const ssize_t maxAllowedMemDiff = MAX_MEM_ALLOWED(connectionsToUse);
    const ssize_t minAllowedMemDiff = maxAllowedMemDiff * 0.75;

    struct s2n_connection **clients = calloc(connectionsToUse, sizeof(struct s2n_connection *));
    struct s2n_connection **servers = calloc(connectionsToUse, sizeof(struct s2n_connection *));

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

    struct s2n_config *client_config;
    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_config *server_config;
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
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        clients[i] = client_conn;

        struct s2n_connection *server_conn;
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

    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_config_free(client_config));

    free(cert_chain);
    free(private_key);
    free(clients);
    free(servers);

    TEST_DEBUG_PRINT("\n");
    TEST_DEBUG_PRINT("VmData initial:              %10zd\n", vm_data_initial);
    TEST_DEBUG_PRINT("VmData after allocations:    %10zd\n", vm_data_after_allocation);
    TEST_DEBUG_PRINT("VmData after handshakes:     %10zd\n", vm_data_after_handshakes);
    TEST_DEBUG_PRINT("VmData after free handshake: %10zd\n", vm_data_after_free_handshake);
    TEST_DEBUG_PRINT("VmData after release:        %10zd\n", vm_data_after_release_buffers);
    TEST_DEBUG_PRINT("Max VmData diff allowed:     %10zd\n", maxAllowedMemDiff);
    TEST_DEBUG_PRINT("Number of connections used:  %10zu\n", connectionsToUse);

    EXPECT_TRUE(vm_data_after_free_handshake <= vm_data_after_handshakes);
    EXPECT_TRUE(vm_data_after_release_buffers <= vm_data_after_free_handshake);

    ssize_t handshake_diff = (vm_data_after_handshakes - vm_data_initial);
    ssize_t allocation_diff = (vm_data_after_allocation - vm_data_initial);

    /*
     * get_vm_data_size is required for this test to succeed.
     * Any platform that doesn't implement get_vm_data_size should be excluded here.
     */
#ifndef __APPLE__
    if (allocation_diff > maxAllowedMemDiff
            || handshake_diff > maxAllowedMemDiff
            || handshake_diff < minAllowedMemDiff) {
        fprintf(stdout, "\nActual KB per connection: %i\n",
                (int) ACTUAL_MEM_PER_CONNECTION(connectionsToUse, handshake_diff));
        FAIL_MSG("Unexpected memory usage. If expected, update MEM_PER_CONNECTION.");
    }
#endif

    END_TEST();
}
