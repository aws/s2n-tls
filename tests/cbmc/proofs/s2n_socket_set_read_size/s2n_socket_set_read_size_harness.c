/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file s2n_socket_set_read_size_harness.c
 * @brief Implements the proof harness for s2n_socket_set_read_size function.
 */

#include <sys/socket.h>
#include <utils/s2n_socket.h>
#include <cbmc_proof/make_common_datastructures.h>

#include <assert.h>

void s2n_socket_set_read_size_harness()
{
  /* Non-deterministic inputs. */
  struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));
  int fd;
  if (s2n_connection != NULL) {
    s2n_connection->recv_io_context = cbmc_allocate_s2n_socket_read_io_context();
  }

  /* Operation under verification. */
  int result = s2n_socket_set_read_size(s2n_connection, fd);

  /* Post-condition. */
  assert(S2N_IMPLIES(result == S2N_SUCCESS, s2n_connection->recv_io_context != NULL));
  assert(S2N_IMPLIES(s2n_connection == NULL, result != S2N_SUCCESS));
}
