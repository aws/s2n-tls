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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "pq-crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#define ZERO_TO_THIRTY_ONE 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

static uint8_t server_ocsp_status[] = {
    /* clang-format off */
        0x30, 0x82, 0x06, 0x45, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x06, 0x3e, 0x30, 0x82, 0x06, 0x3a, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x06, 0x2b, 0x30, 0x82, 0x06, 0x27, 0x30, 0x81, 0xeb, 0xa1, 0x70, 0x30, 0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x4c, 0x31, 0x31, 0x30, 0x2f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x28, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6d, 0x20, 0x4c, 0x74, 0x64, 0x2e, 0x20, 0x28, 0x53, 0x74, 0x61, 0x72, 0x74, 0x20, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x72, 0x63, 0x69, 0x61, 0x6c, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x29, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x23, 0x53, 0x74, 0x61, 0x72,
        0x74, 0x43, 0x6f, 0x6d, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x31, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x35, 0x30, 0x32, 0x32, 0x37, 0x30, 0x36, 0x34, 0x36, 0x34, 0x35, 0x5a, 0x30, 0x66, 0x30, 0x64, 0x30, 0x3c, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x65, 0x68, 0x87, 0x4f, 0x40, 0x75, 0x0f, 0x01, 0x6a, 0x34, 0x75, 0x62, 0x5e, 0x1f, 0x5c, 0x93, 0xe5, 0xa2, 0x6d, 0x58, 0x04, 0x14, 0xeb, 0x42, 0x34, 0xd0, 0x98, 0xb0, 0xab, 0x9f, 0xf4, 0x1b, 0x6b, 0x08, 0xf7, 0xcc, 0x64, 0x2e, 0xef, 0x0e, 0x2c, 0x45, 0x02, 0x03, 0x0f, 0x87, 0x2c, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30,
        0x31, 0x35, 0x30, 0x32, 0x32, 0x37, 0x30, 0x36, 0x34, 0x36, 0x34, 0x35, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x35, 0x30, 0x33, 0x30, 0x31, 0x30, 0x36, 0x34, 0x36, 0x34, 0x35, 0x5a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x3c, 0x16, 0x25, 0xa2, 0x0f, 0x46, 0xc2, 0xa6, 0xac, 0xb1, 0x6e, 0x54, 0xc8, 0xf1, 0x7f, 0xa9, 0xbe, 0x58, 0xf0, 0xdb, 0x81, 0x37, 0x23, 0x76, 0x65, 0x56, 0x90, 0x15, 0xb1, 0x30, 0x6f, 0x43, 0xe2, 0x59, 0x0d, 0x97, 0xa8, 0xa6, 0x05, 0x25, 0xe7, 0x94, 0x21, 0xd5, 0xda, 0x4b, 0x55, 0x13, 0xc7, 0xdf, 0x5d, 0xf6, 0x31, 0xe8, 0x2f, 0x0d, 0xa0, 0xac, 0xd4, 0xfe, 0xf8, 0x22, 0xe7, 0x12, 0xf4, 0x32, 0xcd, 0x53,
        0x03, 0x56, 0x98, 0x0a, 0xf8, 0x9e, 0xda, 0x2c, 0x0a, 0x43, 0x66, 0x6e, 0x0e, 0x9c, 0x9b, 0xf2, 0x0c, 0x66, 0x65, 0x1c, 0x65, 0xc4, 0xf0, 0x82, 0xc3, 0x17, 0x3d, 0x27, 0x11, 0xcc, 0xac, 0x37, 0xe3, 0xa8, 0x35, 0x46, 0x26, 0xcd, 0x08, 0x04, 0xfa, 0xb4, 0xdf, 0x9d, 0x12, 0xdf, 0x45, 0x8d, 0xf2, 0xef, 0x1a, 0xd1, 0x53, 0x50, 0x9a, 0xe3, 0xe8, 0x22, 0xda, 0xec, 0xeb, 0xc0, 0xa8, 0xea, 0xc4, 0x83, 0xc4, 0x47, 0xf2, 0x05, 0x3c, 0x14, 0x11, 0x3b, 0x25, 0xdc, 0xb9, 0x09, 0x5c, 0xd7, 0x74, 0x88, 0x96, 0x82, 0x4d, 0xbb, 0x8b, 0x7f, 0x6a, 0xbf, 0xa1, 0x44, 0x1b, 0x89, 0x67, 0xce, 0x45, 0xab, 0xca, 0xef, 0x48, 0xa6, 0x80, 0x76, 0x7d, 0xbe, 0xb7, 0x8a, 0xdf, 0x7a, 0x32, 0x8c, 0xa5, 0x86, 0x4e, 0x26, 0xf7, 0x15, 0x63, 0xbb,
        0xb1, 0xcc, 0xe0, 0x32, 0x82, 0x02, 0x5d, 0x2b, 0x60, 0x39, 0xdb, 0xd2, 0x04, 0x56, 0xb4, 0x7e, 0xe6, 0x3a, 0x69, 0x0c, 0x8a, 0xf0, 0x00, 0xf4, 0x56, 0xb0, 0xa7, 0x1a, 0x37, 0x05, 0x4b, 0xeb, 0x8c, 0x87, 0x05, 0x37, 0x92, 0xf7, 0x93, 0x5d, 0x93, 0x32, 0x7d, 0x6e, 0xa6, 0xda, 0x10, 0x4b, 0x49, 0xae, 0x86, 0xe4, 0xb4, 0x4d, 0x98, 0x42, 0x3e, 0xd3, 0x42, 0x46, 0x5d, 0xdd, 0x2f, 0x97, 0xd4, 0xb9, 0x7f, 0xbe, 0xa0, 0x82, 0x04, 0x21, 0x30, 0x82, 0x04, 0x1d, 0x30, 0x82, 0x04, 0x19, 0x30, 0x82, 0x03, 0x01, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x15, 0xfa, 0xa9, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x8c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x49, 0x4c, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0d, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6d, 0x20, 0x4c, 0x74, 0x64, 0x2e, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x22, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x44, 0x69, 0x67, 0x69, 0x74, 0x61, 0x6c, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x31, 0x38, 0x30, 0x36, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2f, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6d, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x31, 0x20, 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61,
        0x74, 0x65, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x31, 0x32, 0x32, 0x31, 0x38, 0x33, 0x35, 0x33, 0x37, 0x5a, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35, 0x31, 0x36, 0x33, 0x34, 0x5a, 0x30, 0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x4c, 0x31, 0x31, 0x30, 0x2f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x28, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6d, 0x20, 0x4c, 0x74, 0x64, 0x2e, 0x20, 0x28, 0x53, 0x74, 0x61, 0x72, 0x74, 0x20, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x72, 0x63, 0x69, 0x61, 0x6c, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x29, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
        0x23, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6d, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x31, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb9, 0x56, 0x1b, 0x4c, 0x45, 0x31, 0x87, 0x17, 0x17, 0x80, 0x84, 0xe9, 0x6e, 0x17, 0x8d, 0xf2, 0x25, 0x5e, 0x18, 0xed, 0x8d, 0x8e, 0xcc, 0x7c, 0x2b, 0x7b, 0x51, 0xa6, 0xc1, 0xc2, 0xe6, 0xbf, 0x0a, 0xa3, 0x60, 0x30, 0x66, 0xf1, 0x32, 0xfe, 0x10, 0xae, 0x97, 0xb5, 0x0e, 0x99, 0xfa, 0x24, 0xb8, 0x3f, 0xc5,
        0x3d, 0xd2, 0x77, 0x74, 0x96, 0x38, 0x7d, 0x14, 0xe1, 0xc3, 0xa9, 0xb6, 0xa4, 0x93, 0x3e, 0x2a, 0xc1, 0x24, 0x13, 0xd0, 0x85, 0x57, 0x0a, 0x95, 0xb8, 0x14, 0x74, 0x14, 0xa0, 0xbc, 0x00, 0x7c, 0x7b, 0xcf, 0x22, 0x24, 0x46, 0xef, 0x7f, 0x1a, 0x15, 0x6d, 0x7e, 0xa1, 0xc5, 0x77, 0xfc, 0x5f, 0x0f, 0xac, 0xdf, 0xd4, 0x2e, 0xb0, 0xf5, 0x97, 0x49, 0x90, 0xcb, 0x2f, 0x5c, 0xef, 0xeb, 0xce, 0xef, 0x4d, 0x1b, 0xdc, 0x7a, 0xe5, 0xc1, 0x07, 0x5c, 0x5a, 0x99, 0xa9, 0x31, 0x71, 0xf2, 0xb0, 0x84, 0x5b, 0x4f, 0xf0, 0x86, 0x4e, 0x97, 0x3f, 0xcf, 0xe3, 0x2f, 0x9d, 0x75, 0x11, 0xff, 0x87, 0xa3, 0xe9, 0x43, 0x41, 0x0c, 0x90, 0xa4, 0x49, 0x3a, 0x30, 0x6b, 0x69, 0x44, 0x35, 0x93, 0x40, 0xa9, 0xca, 0x96, 0xf0, 0x2b, 0x66, 0xce, 0x67,
        0xf0, 0x28, 0xdf, 0x29, 0x80, 0xa6, 0xaa, 0xee, 0x8d, 0x5d, 0x5d, 0x45, 0x2b, 0x8b, 0x0e, 0xb9, 0x3f, 0x92, 0x3c, 0xc1, 0xe2, 0x3f, 0xcc, 0xcb, 0xdb, 0xe7, 0xff, 0xcb, 0x11, 0x4d, 0x08, 0xfa, 0x7a, 0x6a, 0x3c, 0x40, 0x4f, 0x82, 0x5d, 0x1a, 0x0e, 0x71, 0x59, 0x35, 0xcf, 0x62, 0x3a, 0x8c, 0x7b, 0x59, 0x67, 0x00, 0x14, 0xed, 0x06, 0x22, 0xf6, 0x08, 0x9a, 0x94, 0x47, 0xa7, 0xa1, 0x90, 0x10, 0xf7, 0xfe, 0x58, 0xf8, 0x41, 0x29, 0xa2, 0x76, 0x5e, 0xa3, 0x67, 0x82, 0x4d, 0x1c, 0x3b, 0xb2, 0xfd, 0xa3, 0x08, 0x53, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0xa0, 0x30, 0x81, 0x9d, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x03, 0xa8,
        0x30, 0x1e, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x17, 0x30, 0x15, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x45, 0xe0, 0xa3, 0x66, 0x95, 0x41, 0x4c, 0x5d, 0xd4, 0x49, 0xbc, 0x00, 0xe3, 0x3c, 0xdc, 0xdb, 0xd2, 0x34, 0x3e, 0x17, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xeb, 0x42, 0x34, 0xd0, 0x98, 0xb0, 0xab, 0x9f, 0xf4, 0x1b, 0x6b, 0x08, 0xf7, 0xcc, 0x64, 0x2e, 0xef, 0x0e, 0x2c, 0x45, 0x30, 0x23, 0x06, 0x03, 0x55, 0x1d, 0x12, 0x04, 0x1c, 0x30, 0x1a, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
        0x73, 0x74, 0x61, 0x72, 0x74, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x42, 0xcd, 0x4c, 0x03, 0xd2, 0x9a, 0x55, 0xb2, 0xd6, 0x3e, 0x90, 0x4c, 0x89, 0x27, 0xd0, 0xcf, 0x87, 0xf6, 0x91, 0x9b, 0x86, 0x6a, 0x6d, 0x76, 0xd9, 0x5e, 0xbc, 0xc8, 0xfe, 0x74, 0xbe, 0x97, 0x29, 0xd1, 0xac, 0x92, 0x9b, 0x9e, 0x48, 0xab, 0xb1, 0xf4, 0xbe, 0xd5, 0x3f, 0xa8, 0x4c, 0xce, 0x0e, 0x2f, 0x39, 0x96, 0x4b, 0xde, 0xda, 0xac, 0x40, 0xce, 0xbb, 0x93, 0xdb, 0x1c, 0x39, 0x02, 0x03, 0x25, 0x32, 0x45, 0xde, 0x94, 0x5a, 0x63, 0xaf, 0xf7, 0xb0, 0x70, 0xc8, 0xcc, 0x2b, 0x34, 0x7b, 0x5f, 0x7d, 0xc6, 0x96, 0x1d, 0x59,
        0x1d, 0xdd, 0x8f, 0x7e, 0x55, 0xc4, 0x92, 0x11, 0x8d, 0xd9, 0x11, 0x11, 0x22, 0x20, 0xd3, 0x56, 0x1e, 0x11, 0xae, 0x97, 0xf2, 0x71, 0xea, 0x8c, 0xf5, 0x15, 0x2d, 0xb1, 0x59, 0xdd, 0x3e, 0x43, 0x9c, 0xf1, 0xda, 0x81, 0xd7, 0xc8, 0x6c, 0xf6, 0x08, 0x5d, 0x6f, 0xdf, 0x26, 0xa8, 0xfe, 0x84, 0xa2, 0x08, 0xaf, 0xdb, 0x9b, 0x39, 0xf5, 0x46, 0xfa, 0x5b, 0xfa, 0x97, 0x64, 0x1d, 0xf1, 0xd4, 0xbc, 0xb0, 0xa4, 0x2f, 0x36, 0xf1, 0x90, 0xb5, 0x3b, 0x67, 0x0b, 0x5b, 0xf3, 0x24, 0x50, 0x27, 0x63, 0xdc, 0xeb, 0xb6, 0x55, 0x0f, 0xb7, 0xbe, 0xee, 0x2e, 0xfb, 0xc8, 0x6a, 0x10, 0xab, 0xee, 0x9a, 0x27, 0xe4, 0x13, 0x16, 0xcf, 0xdd, 0x13, 0xa7, 0x0f, 0xde, 0x61, 0x8c, 0xfa, 0xed, 0x2d, 0x00, 0x60, 0xf9, 0xc4, 0x3d, 0xad, 0xd6, 0xa2,
        0xc0, 0xa3, 0x29, 0x11, 0x61, 0x0b, 0x65, 0xdb, 0x14, 0x79, 0xb1, 0x7d, 0x8a, 0x57, 0x91, 0x59, 0xa4, 0xfc, 0x4c, 0x60, 0x4f, 0x3c, 0xc8, 0x31, 0x9b, 0x69, 0x70, 0xb9, 0xae, 0xed, 0xb1, 0xde, 0x58, 0x8d, 0x62, 0x30, 0xb4, 0x7b, 0x46, 0xf2, 0xda, 0x7b, 0xbb, 0x72, 0xcf, 0xf0, 0x47, 0x8b, 0x84,
    /* clang-format on */
};

/* This data format is bogus, but sufficient to test the server is able
   to return correctly what has been configured.  Once the client does
   validation we will need real data here.
 */
static uint8_t sct_list[] = {
    0xff, 0xff, 0xff, 0xff, 0xff
};

message_type_t s2n_conn_get_current_message_type(struct s2n_connection *conn);

/* Helper function to allow us to easily repeat the PQ extension test for many scenarios.
 * If the KEM negotiation is expected to fail (because of e.g. a client/server extension
 * mismatch), pass in expected_kem_id = -1. The tests should always EXPECT_SUCCESS when
 * calling this function. */
static int negotiate_kem(const uint8_t client_extensions[], const size_t client_extensions_len,
        const uint8_t client_hello_message[], const size_t client_hello_len,
        const char cipher_pref_version[], const int expected_kem_id, struct s2n_test_io_pair *io_pair)
{
    char *cert_chain;
    char *private_key;

    POSIX_GUARD_PTR(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD_PTR(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(setenv("S2N_DONT_MLOCK", "1", 0));

    struct s2n_connection *server_conn;
    struct s2n_config *server_config;
    s2n_blocked_status server_blocked;
    struct s2n_cert_chain_and_key *chain_and_key;

    size_t body_len = client_hello_len + client_extensions_len;
    uint8_t message_header[] = {
        /* Handshake message type CLIENT HELLO */
        0x01,
        /* Body len */
        (body_len >> 16) & 0xff,
        (body_len >> 8) & 0xff,
        (body_len & 0xff),
    };
    size_t message_header_len = sizeof(message_header);
    size_t message_len = message_header_len + body_len;
    uint8_t record_header[] = {
        /* Record type HANDSHAKE */
        0x16,
        /* Protocol version TLS 1.2 */
        0x03,
        0x03,
        /* Message len */
        (message_len >> 8) & 0xff,
        (message_len & 0xff),
    };
    size_t record_header_len = sizeof(record_header);

    POSIX_GUARD_PTR(server_conn = s2n_connection_new(S2N_SERVER));
    POSIX_GUARD(s2n_connection_set_io_pair(server_conn, io_pair));

    POSIX_GUARD_PTR(server_config = s2n_config_new());
    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD_PTR(chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    POSIX_GUARD(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    POSIX_GUARD(s2n_config_set_cipher_preferences(server_config, cipher_pref_version));
    POSIX_GUARD(s2n_connection_set_config(server_conn, server_config));
    server_conn->kex_params.kem_params.kem = NULL;

    /* Send the client hello */
    POSIX_ENSURE_EQ(write(io_pair->client, record_header, record_header_len), (int64_t) record_header_len);
    POSIX_ENSURE_EQ(write(io_pair->client, message_header, message_header_len), (int64_t) message_header_len);
    POSIX_ENSURE_EQ(write(io_pair->client, client_hello_message, client_hello_len), (int64_t) client_hello_len);
    POSIX_ENSURE_EQ(write(io_pair->client, client_extensions, client_extensions_len), (int64_t) client_extensions_len);

    POSIX_GUARD(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
    if (s2n_negotiate(server_conn, &server_blocked) == 0) {
        /* We expect the overall negotiation to fail and return non-zero, but it should get far enough
         * that a KEM extension was agreed upon. */
        return S2N_FAILURE;
    }

    int negotiated_kem_id;

    if (server_conn->kex_params.kem_params.kem != NULL) {
        negotiated_kem_id = server_conn->kex_params.kem_params.kem->kem_extension_id;
    } else {
        negotiated_kem_id = -1;
    }

    POSIX_GUARD(s2n_connection_free(server_conn));
    POSIX_GUARD(s2n_cert_chain_and_key_free(chain_and_key));
    POSIX_GUARD(s2n_config_free(server_config));

    free(cert_chain);
    free(private_key);

    POSIX_ENSURE_EQ(negotiated_kem_id, expected_kem_id);

    return 0;
}

int main(int argc, char **argv)
{
    char *cert_chain = NULL;
    char *private_key = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Create nonblocking pipes */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    /* Client doesn't use the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_cert_chain_and_key *chain_and_key;

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server didn't receive the server name. */
        EXPECT_NULL(s2n_get_server_name(server_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Client uses the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_cert_chain_and_key *chain_and_key;

        const char *sent_server_name = "www.alligator.com";
        const char *received_server_name;

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        /* Set the server name */
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, sent_server_name));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ALLIGATOR_SAN_CERT, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ALLIGATOR_SAN_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Client sends multiple server names. */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        const char *sent_server_name = "svr";
        const char *received_server_name;
        struct s2n_cert_chain_and_key *chain_and_key;
        uint32_t cert_chain_len = 0;
        uint32_t private_key_len = 0;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00,
            0x00,
            /* Extension size */
            0x00,
            0x0C,
            /* All server names len */
            0x00,
            0x0A,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00,
            0x03,
            /* First server name, matches sent_server_name */
            's',
            'v',
            'r',
            /* Second server name type - host name */
            0x00,
            /* Second server name len */
            0x00,
            0x01,
            /* Second server name */
            0xFF,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00,
            0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff,
            (body_len >> 8) & 0xff,
            (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version garbage value. s2n should still accept this. */
            0x01,
            0x01,
            /* Message len */
            (message_len >> 8) & 0xff,
            (message_len & 0xff),
        };

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        /* Security policy must allow cipher suite hard coded into client hello */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_TEST_CERT_CHAIN, (uint8_t *) cert_chain, &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_TEST_PRIVATE_KEY, (uint8_t *) private_key, &private_key_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, (uint8_t *) cert_chain, cert_chain_len, (uint8_t *) private_key, private_key_len));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(io_pair.client, client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));
        EXPECT_TRUE(server_conn->alert_sent);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
    };

    /* Client sends duplicate server name extension */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        struct s2n_cert_chain_and_key *chain_and_key;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00,
            0x00,
            /* Extension size */
            0x00,
            0x0C,
            /* All server names len */
            0x00,
            0x0A,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00,
            0x03,
            /* First server name, matches sent_server_name */
            's',
            'v',
            'r',
            /* Second server name type - host name */
            0x00,
            /* Second server name len */
            0x00,
            0x01,
            /* Second server name */
            0xFF,
            /* And all that again... */
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00,
            0x00,
            /* Extension size */
            0x00,
            0x0C,
            /* All server names len */
            0x00,
            0x0A,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00,
            0x03,
            /* First server name, matches sent_server_name */
            's',
            'v',
            'r',
            /* Second server name type - host name */
            0x00,
            /* Second server name len */
            0x00,
            0x01,
            /* Second server name */
            0xFF,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00,
            0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff,
            (body_len >> 8) & 0xff,
            (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Message len */
            (message_len >> 8) & 0xff,
            (message_len & 0xff),
        };

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(io_pair.client, client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that we fail for duplicated extension type Bad Message */
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_DUPLICATE_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
    };

    /* Client sends a valid initial renegotiation_info */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        struct s2n_cert_chain_and_key *chain_and_key;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff,
            0x01,
            /* Extension size */
            0x00,
            0x01,
            /* Empty renegotiated_connection */
            0x00,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00,
            0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff,
            (body_len >> 8) & 0xff,
            (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Message len */
            (message_len >> 8) & 0xff,
            (message_len & 0xff),
        };

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        /* Security policy must allow cipher suite hard coded into client hello */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(io_pair.client, client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type & NEGOTIATED, NEGOTIATED);

        /* Verify that the that we detected secure_renegotiation */
        EXPECT_EQUAL(server_conn->secure_renegotiation, 1);

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));
        EXPECT_TRUE(server_conn->alert_sent);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
    };

    /* Client sends a non-empty initial renegotiation_info */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        struct s2n_cert_chain_and_key *chain_and_key;
        uint8_t buf[5120];

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff,
            0x01,
            /* Extension size */
            0x00,
            0x21,
            /* renegotiated_connection len */
            0x20,
            /* fake renegotiated_connection */
            ZERO_TO_THIRTY_ONE,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00,
            0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff,
            (body_len >> 8) & 0xff,
            (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Message len */
            (message_len >> 8) & 0xff,
            (message_len & 0xff),
        };

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(io_pair.client, record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(io_pair.client, message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(io_pair.client, client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(io_pair.client, client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that we fail for non-empty renegotiated_connection */
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));

        /* Clear pipe since negotiation failed mid-handshake */
        EXPECT_SUCCESS(read(io_pair.client, buf, sizeof(buf)));
    };

    /* Client doesn't use the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        uint32_t length;

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING,
                server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server didn't send an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 0);

        /* Verify that the client didn't receive an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 0);
        EXPECT_NULL(s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Cannot enable OCSP stapling if there's no support for it */
    if (!s2n_x509_ocsp_stapling_supported()) {
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_FAILURE(s2n_config_set_check_stapled_ocsp_response(client_config, 1));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /* Server doesn't support the OCSP extension. We can't run this test if ocsp isn't supported by the client. */
    if (s2n_x509_ocsp_stapling_supported()) {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        uint32_t length;
        struct s2n_cert_chain_and_key *chain_and_key;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server didn't send an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 0);

        /* Verify that the client didn't receive an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 0);
        EXPECT_NULL(s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /* Test with s2n_config_set_extension_data(). Can be removed once API is deprecated */
    if (s2n_x509_ocsp_stapling_supported()) {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        uint32_t length;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING,
                server_ocsp_status, sizeof(server_ocsp_status)));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server sent an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 1);

        /* Verify that the client received an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 1);
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (size_t i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /* Server and client support the OCSP extension. Test only runs if ocsp stapled responses are supported by the client */
    if (s2n_x509_ocsp_stapling_supported()) {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        uint32_t length;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING,
                server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server sent an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 1);

        /* Verify that the client received an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 1);
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (size_t i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /* Server and client support the OCSP extension. Test Behavior for TLS 1.3 */
    if (s2n_x509_ocsp_stapling_supported() && s2n_is_tls13_fully_supported()) {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        uint32_t length;

        EXPECT_SUCCESS(s2n_enable_tls13_in_test());

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS13;
        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->client_protocol_version = S2N_TLS13;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->client_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING,
                server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server sent an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(server_conn), 1);

        /* Verify that the client received an OCSP response. */
        EXPECT_EQUAL(s2n_connection_is_ocsp_stapled(client_conn), 1);

        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (size_t i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    }

    /* Client does not request SCT, but server is configured to serve them. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;

        uint32_t length;

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY,
                sct_list, sizeof(sct_list)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client did *not* receive an SCT list */
        EXPECT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
    };

    /* Client requests SCT and server does have it. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *client_config;
        struct s2n_config *server_config;

        uint32_t length;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        /* Indicate that the client wants CT if available */
        EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY,
                sct_list, sizeof(sct_list)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client did receive an SCT list */
        EXPECT_NOT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(sct_list));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Client requests SCT and server does *not* have it. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *client_config;
        struct s2n_config *server_config;
        struct s2n_cert_chain_and_key *chain_and_key;

        uint32_t length;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        /* Indicate that the client wants CT if available */
        EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client does not get a list */
        EXPECT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Client requests 512, 1024, 2048, and 4096 maximum fragment lengths */
    for (uint8_t mfl_code = S2N_TLS_MAX_FRAG_LEN_512; mfl_code <= S2N_TLS_MAX_FRAG_LEN_4096; mfl_code++) {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        struct s2n_cert_chain_and_key *chain_and_key;

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(client_config, mfl_code));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(server_config));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Preference should be ignored as the TlS Maximum Fragment Length Extension is Set */
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(server_conn));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, mfl_code_to_length[mfl_code]);
        EXPECT_EQUAL(server_conn->negotiated_mfl_code, mfl_code);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /* Client requests invalid maximum fragment length */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        struct s2n_cert_chain_and_key *chain_and_key;

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_FAILURE(s2n_config_send_max_fragment_length(client_config, 5));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(server_config));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* check that max_fragment_length did not get set due to invalid mfl_code */
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_EXT_NONE);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Server ignores client's request of S2N_TLS_MAX_FRAG_LEN_2048 maximum fragment length when accept_mfl is not set*/
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        struct s2n_cert_chain_and_key *chain_and_key;

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(client_config, S2N_TLS_MAX_FRAG_LEN_2048));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* check that max_fragment_length did not get set since accept_mfl is not set */
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->negotiated_mfl_code, S2N_TLS_MAX_FRAG_LEN_EXT_NONE);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* All PQ KEM byte values are from https://tools.ietf.org/html/draft-campagna-tls-bike-sike-hybrid */
    {
        /* Client requests Kyber ciphersuite but sends only PQ KEM extensions with bogus
         * extension IDs; server is using the round 3 preference list. Expect to negotiate no KEM (-1) whether or
         * not PQ is enabled. */
        int expected_kem_id = -1;

        uint8_t client_extensions[] = {
            /* Extension type pq_kem_parameters */
            0xFE,
            0x01,
            /* Extension size */
            0x00,
            0x08,
            /* KEM names len */
            0x00,
            0x06,
            /* KEM values out of range of anything s2n supports */
            0xcc,
            0x05,
            0xaa,
            0xbb,
            0xff,
            0xa1,
        };
        size_t client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 */
            0xFF,
            0x0C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        size_t client_hello_len = sizeof(client_hello_message);
        EXPECT_SUCCESS(negotiate_kem(client_extensions, client_extensions_len, client_hello_message,
                client_hello_len, "PQ-TLS-1-0-2021-05-24", expected_kem_id, &io_pair));
    };

    {
        /* Client sends PQ KEM extension with BIKE extensions, but requests SIKE ciphersuite;
         * server is using the round 1 only preference list. Expect to negotiate no KEM (-1)
         * whether or not PQ is enabled. */
        int expected_kem_id = -1;

        uint8_t client_extensions[] = {
            /* Extension type pq_kem_parameters */
            0xFE,
            0x01,
            /* Extension size */
            0x00,
            0x06,
            /* KEM names len */
            0x00,
            0x04,
            /* BIKE1_L1_R1 */
            0x00,
            0x01,
            /* BIKE1_L1_R2 */
            0x00,
            0x0D,
        };
        size_t client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 */
            0xFF,
            0x08,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        size_t client_hello_len = sizeof(client_hello_message);
        EXPECT_SUCCESS(negotiate_kem(client_extensions, client_extensions_len, client_hello_message,
                client_hello_len, "KMS-PQ-TLS-1-0-2019-06", expected_kem_id, &io_pair));
    };

    {
        /* Client sends PQ KEM extensions for round 2 only; the server is using the round 1
         * only preference list. Expect to negotiate no KEM (-1) whether or not PQ is enabled. */
        int expected_kem_id = -1;

        uint8_t client_extensions[] = {
            /* Extension type pq_kem_parameters */
            0xFE,
            0x01,
            /* Extension size */
            0x00,
            0x06,
            /* KEM names len */
            0x00,
            0x04,
            /* SIKE_P434_R3 */
            0x00,
            0x13,
            /* BIKE1_L1_R2 */
            0x00,
            0x0D,
        };
        size_t client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03,
            0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00,
            0x02,
            /* Cipher suite - TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 */
            0xFF,
            0x08,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff,
            (client_extensions_len & 0xff),
        };
        size_t client_hello_len = sizeof(client_hello_message);
        EXPECT_SUCCESS(negotiate_kem(client_extensions, client_extensions_len, client_hello_message,
                client_hello_len, "KMS-PQ-TLS-1-0-2019-06", expected_kem_id, &io_pair));
    };

    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    free(cert_chain);
    free(private_key);
    END_TEST();
    return 0;
}
