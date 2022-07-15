/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file s2n_socket_read_harness.c
 * @brief Implements the proof harness for s2n_socket_read function.
 */

#include "utils/s2n_socket.h"
#include "cbmc_proof/make_common_datastructures.h"

#include <assert.h>

void s2n_socket_read_harness()
{
  /* Non-deterministic inputs. */
  void *io_context = cbmc_allocate_s2n_socket_read_io_context();
  const uint8_t *buf = malloc(sizeof(*buf));
  uint32_t len;
  
  /* Operation under verification. */
  int result = s2n_socket_read(io_context, buf, len);

  /* Post-condition. */
  assert(S2N_IMPLIES(result >= 0, io_context != NULL));
  assert(S2N_IMPLIES(io_context == NULL, result != S2N_SUCCESS));
}
