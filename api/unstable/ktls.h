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

#pragma once

#include <s2n.h>

/**
 * @file ktls.h
 *
 * The following APIs enable applications to use kernel TLS (kTLS), meaning that
 * encrypting and decrypting TLS records is handled by the kernel rather than by
 * the s2n-tls library.
 *
 * The kTLS APIs are currently considered unstable. kTLS is a relatively new
 * feature with limited and volatile support from different kernels and hardware.
 *
 * Currently, s2n-tls supports ktls for only very limited scenarios:
 * - You must be using Linux. We have not tested with other kernels.
 * - Your kernel must support kTLS. For Linux, versions >4.13 should support kTLS.
 * - The TLS kernel module must be enabled. While some environments enable the
 *   module by default, most will require you to run `sudo modprobe tls`.
 * - You must negotiate TLS1.2. TLS1.3 support is blocked on kernel support for
 *   TLS KeyUpdate messages.
 * - You must negotiate AES128-GCM, which is the most preferred cipher suite
 *   in the "default" security policy. Other ciphers are supported by the kernel,
 *   but not implemented in s2n-tls yet.
 */

/**
 * Enables sending using kTLS on a given connection.
 *
 * See above for the limitations on when kTLS can be enabled. Additionally,
 * s2n_connection_ktls_enable_send must be called after the handshake completes.
 * It may be called after some application data is sent and received without kTLS,
 * but there must be no pending application data that requires flushing. If these
 * requirements are not met, enabling kTLS will fail with an error.
 *
 * After kTLS is enabled for sending, s2n_send, s2n_sendv, and s2n_sendv_with_offset
 * will use kTLS. kTLS should result in memory and CPU savings. s2n_sendfile will
 * also become available.
 *
 * For applications using kTLS to avoid copying or allocating memory, s2n_sendv
 * should be preferred over s2n_sendv_with_offset. For s2n_sendv_with_offset,
 * s2n-tls may need to copy the provided iovec array to apply the offset, and may
 * need to allocate memory to copy large (>16) iovec arrays.
 *
 * If kTLS is enabled for sending, s2n_connection_get_wire_bytes_out will always
 * return 0 instead of an accurate count.
 *
 * @warning Due to the uncertainty around kTLS support, the signature of this
 * method is likely to change before kTLS is marked as stable.
 *
 * @param conn A pointer to the connection.
 * @returns S2N_SUCCESS if kTLS is successfully enabled. If kTlS is not successfully
 * enabled, returns S2N_FAILURE but the connection may proceed without kTLS.
 */
S2N_API int s2n_connection_ktls_enable_send(struct s2n_connection *conn);

/**
 * Enables receiving using kTLS on a given connection.
 *
 * See above for the limitations on when kTLS can be enabled. Additionally,
 * s2n_connection_ktls_enable_recv must be called after the handshake completes.
 * It may be called after some application data is sent and received without kTLS,
 * but there must be no buffered application data that requires draining. If these
 * requirements are not met, enabling kTLS will fail with an error.
 *
 * After kTLS is enabled for receiving, s2n_recv will use kTLS. This may result
 * in memory and CPU savings, but currently will still buffer and copy application data.
 * We will further optimize s2n_recv for kTLS in the future.
 *
 * If kTLS is enabled for receiving, s2n_connection_get_wire_bytes_in will always
 * return 0 instead of an accurate count.
 *
 * @warning Due to the uncertainty around kTLS support, the signature of this
 * method is likely to change before kTLS is marked as stable.
 *
 * @param conn A pointer to the connection.
 * @returns S2N_SUCCESS if kTLS is successfully enabled. If kTlS is not successfully
 * enabled, returns S2N_FAILURE but the connection may proceed without kTLS.
 */
S2N_API int s2n_connection_ktls_enable_recv(struct s2n_connection *conn);

/**
 * Sends the contents of a file as application data.
 *
 * s2n_sendfile should be more efficient than s2n_send because the copy between
 * the file and the write socket happens inside the kernel.
 *
 * This method is only supported if kTLS is enabled for sending.
 *
 * @param conn A pointer to the connection.
 * @param fd The file descriptor to read from. It must be opened for reading and
 * support mmap-like operations (i.e., it cannot be a socket).
 * @param offset The offset in the file to begin reading at.
 * @param count The maximum number of bytes to read from the file.
 * @param bytes_written Will be set to the number of bytes written if successful.
 * @param blocked Will be set to the blocked status if an `S2N_ERR_T_BLOCKED` error is returned.
 * @returns S2N_SUCCESS if any bytes are successfully written, S2N_FAILURE otherwise.
 */
S2N_API int s2n_sendfile(struct s2n_connection *conn, int fd, off_t offset, size_t count,
        size_t *bytes_written, s2n_blocked_status *blocked);
