/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define ZERO_TO_THIRTY_ONE  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

static uint8_t server_ocsp_status[] = {
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
};

/* This data format is bogus, but sufficient to test the server is able
   to return correctly what has been configured.  Once the client does
   validation we will need real data here.
 */
static uint8_t sct_list[] = {
    0xff, 0xff, 0xff, 0xff, 0xff
};


static char certificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n"
    "wEs=\n"
    "-----END CERTIFICATE-----\n";

static char private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyJbWlJh4PhuyHWtlwrREMdWHlg1+NVNswSm2NJU/mrl3/NXE\n"
    "93WE3XyW5W/r+Ak1mhjaH6IHM3m5vAdvzhfRfllpCgCYSrEzwBO/0jQHYuBKr+BX\n"
    "zW1ipBm+MWnMcW+Dx9lz/VdwoSepTEiN1evBZhH+JHBDdeFfL7nyAuRxPy0+IAjw\n"
    "yeFH1FGwIBIUnm0+q/yhWAeU9wHg3NVXZ2mkW5az+isDOOb07NCItPf2K5cwcWkz\n"
    "zIyxgimvCTL/D1tkdFPVgqh5swR/lt0PcT634QiJ5uCVqG/FoDNTbomLsxQdAjWk\n"
    "HHTEu4dGmRAFZ2soUPevz2naYyjRNC7q/Z1MWwIDAQABAoIBAHrkryLrJwAmR8Hu\n"
    "grH/b6h4glFUgvZ43jCaNZ+RsR5Cc1jcP4i832Izat+26oNUYRrADyNCSdcnxLuG\n"
    "cuF5hkg6zzfplWRtnJ8ZenR2m+/gKuIGOMULN1wCyZvMjg0RnVNbzsxwPfj+K6Mo\n"
    "8H0Xq621aFc60JnwMjkzWyqaeyeQogn1pqybuL6Dm2huvN49LR64uHuDUStTRX33\n"
    "ou1fVWXOJ1kealYPbRPj8pDa31omB8q5Cf8Qe/b9anqyi9CsP17QbVg9k2IgoLlj\n"
    "agqOc0u/opOTZB4tqJbqsIdEhc5LD5RUkYJsw00Iq0RSiKTfiWSPyOFw99Y9Act0\n"
    "cbIIxEECgYEA8/SOsQjoUX1ipRvPbfO3suV1tU1hLCQbIpv7WpjNr1kHtngjzQMP\n"
    "dU/iriUPGF1H+AxJJcJQfCVThV1AwFYVKb/LCrjaxlneZSbwfehpjo+xQGaNYG7Q\n"
    "1vQuBVejuYk/IvpZltQOdm838DjvYyWDMh4dcMFIycXxEg+oHxf/s+8CgYEA0n4p\n"
    "GBuLUNx9vv3e84BcarLaOF7wY7tb8z2oC/mXztMZpKjovTH0PvePgI5/b3KQ52R0\n"
    "8zXHVX/4lSQVtCuhOVwKOCQq97/Zhlp5oTTShdQ0Qa1GQRl5wbTS6hrYEWSi9AQP\n"
    "BVUPZ+RIcxx00DfBNURkId8xEpvCOmvySN8sUlUCgYAtXmHbEqkB3qulwRJGhHi5\n"
    "UGsfmJBlwSE6wn9wTdKStZ/1k0o1KkiJrJ2ffUzdXxuvSbmgyA5nyBlMSBdurZOp\n"
    "+/0qtU4abUQq058OC1b2KEryix/nuzQjha25WJ8eNiQDwUNABZfa9rwUdMIwUh2g\n"
    "CHG5Mnjy7Vjz3u2JOtFXCQKBgQCVRo1EIHyLauLuaMINM9HWhWJGqeWXBM8v0GD1\n"
    "pRsovQKpiHQNgHizkwM861GqqrfisZZSyKfFlcynkACoVmyu7fv9VoD2VCMiqdUq\n"
    "IvjNmfE5RnXVQwja+668AS+MHi+GF77DTFBxoC5VHDAnXfLyIL9WWh9GEBoNLnKT\n"
    "hVm8RQKBgQCB9Skzdftc+14a4Vj3NCgdHZHz9mcdPhzJXUiQyZ3tYhaytX9E8mWq\n"
    "pm/OFqahbxw6EQd86mgANBMKayD6B1Id1INqtXN1XYI50bSs1D2nOGsBM7MK9aWD\n"
    "JXlJ2hwsIc4q9En/LR3GtBaL84xTHGfznNylNhXi7GbO1wNMJuAukA==\n"
    "-----END RSA PRIVATE KEY-----\n";

extern message_type_t s2n_conn_get_current_message_type(struct s2n_connection *conn);

static int s2n_negotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    int server_rc = -1;
    s2n_blocked_status server_blocked;
    int client_rc = -1;
    s2n_blocked_status client_blocked;
    do {
        if (client_rc == -1) {
            client_rc = s2n_negotiate(client_conn, &client_blocked);
        }
        if (server_rc == -1) {
            server_rc = s2n_negotiate(server_conn, &server_blocked);
        }
    } while ((server_blocked || client_blocked) && errno == EAGAIN);

    return (server_rc || client_rc);
}

static int s2n_shutdown_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    int server_rc = -1;
    s2n_blocked_status server_blocked;
    int client_rc = -1;
    s2n_blocked_status client_blocked;
    do {
        if (server_rc == -1) {
            server_rc = s2n_shutdown(server_conn, &server_blocked);
        }
        if (client_rc == -1) {
            client_rc = s2n_shutdown(client_conn, &client_blocked);
        }
    } while ((server_blocked || client_blocked) && errno == EAGAIN);

    return (server_rc || client_rc);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));
    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Client doesn't use the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server didn't receive the server name. */
        EXPECT_NULL(s2n_get_server_name(server_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client uses the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        const char *sent_server_name = "awesome.amazonaws.com";
        const char *received_server_name;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Set the server name */
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, sent_server_name));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends multiple server names. */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        int server_to_client[2];
        int client_to_server[2];
        const char *sent_server_name = "svr";
        const char *received_server_name;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00, 0x00,
            /* Extension size */
            0x00, 0x0C,
            /* All server names len */
            0x00, 0x0A,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00, 0x03,
            /* First server name, matches sent_server_name */
            's', 'v', 'r',
            /* Second server name type - host name */
            0x00,
            /* Second server name len */
            0x00, 0x01,
            /* Second server name */
            0xFF,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00, 0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        /* Not a real tls client but make sure we block on its close_notify */
        int shutdown_rc = s2n_shutdown(server_conn, &server_blocked);
        EXPECT_EQUAL(shutdown_rc, -1);
        EXPECT_EQUAL(errno, EAGAIN);
        EXPECT_EQUAL(server_conn->close_notify_queued, 1);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends a valid initial renegotiation_info */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff, 0x01,
            /* Extension size */
            0x00, 0x01,
            /* Empty renegotiated_connection */
            0x00,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00, 0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type & NEGOTIATED, NEGOTIATED);

        /* Verify that the that we detected secure_renegotiation */
        EXPECT_EQUAL(server_conn->secure_renegotiation, 1);

        /* Not a real tls client but make sure we block on its close_notify */
        int shutdown_rc = s2n_shutdown(server_conn, &server_blocked);
        EXPECT_EQUAL(shutdown_rc, -1);
        EXPECT_EQUAL(errno, EAGAIN);
        EXPECT_EQUAL(server_conn->close_notify_queued, 1);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends a non-empty initial renegotiation_info */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff, 0x01,
            /* Extension size */
            0x00, 0x21,
            /* renegotiated_connection len */
            0x20,
            /* fake renegotiated_connection */
            ZERO_TO_THIRTY_ONE,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00, 0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that we fail for non-empty renegotiated_connection */
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client doesn't use the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client didn't receive an OCSP response. */
        EXPECT_NULL(s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Server doesn't support the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client didn't receive an OCSP response. */
        EXPECT_NULL(s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Server and client support the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client received an OCSP response. */
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (int i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client does not request SCT, but server is configured to serve them. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, sct_list, sizeof(sct_list)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client did *not* receive an SCT list */
        EXPECT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client requests SCT and server does have it. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *client_config;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Indicate that the client wants CT if available */
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, sct_list, sizeof(sct_list)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client did receive an SCT list */
        EXPECT_NOT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(sct_list));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client requests SCT and server does *not* have it. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *client_config;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Indicate that the client wants CT if available */
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client does not get a list */
        EXPECT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    END_TEST();
    return 0;
}

