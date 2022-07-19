/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file s2n_socket_is_ipv6_harness.c
 * @brief Implements the proof harness for s2n_socket_is_ipv6 function.
 */

#include <utils/s2n_socket.h>

#include <assert.h>

void s2n_socket_is_ipv6_harness()
{
  /* Non-deterministic inputs. */
  int fd;
  uint8_t *ipv6 = malloc(sizeof(*ipv6));

  /* Operation under verification. */
  int result = s2n_socket_is_ipv6(fd, ipv6);

  /* Post-condition. */
  assert(S2N_IMPLIES(result == S2N_SUCCESS, (ipv6 != NULL && (*ipv6 == 0 || *ipv6 == 1))));
  assert(S2N_IMPLIES(ipv6 == NULL, result != S2N_SUCCESS));
}
