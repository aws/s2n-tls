/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file s2n_socket_was_corked_harness.c
 * @brief Implements the proof harness for s2n_socket_was_corked function.
 */

#include <utils/s2n_socket.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_socket_was_corked_harness()
{
  /* Non-deterministic inputs. */
  struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));
  if (s2n_connection != NULL) {
    s2n_connection->send_io_context = cbmc_allocate_s2n_socket_write_io_context();
  }
  
  /* Operation under verification. */
  int result = s2n_socket_was_corked(s2n_connection);

  /* Post-condition. */
  assert(S2N_IMPLIES(s2n_connection != NULL && (!s2n_connection->managed_io || !s2n_connection->send), result == 0)); /* false */
  assert(S2N_IMPLIES(s2n_connection == NULL, result != 0));
}
