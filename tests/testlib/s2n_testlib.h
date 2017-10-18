/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"

/* Read and write hex */
extern int s2n_stuffer_read_hex(struct s2n_stuffer *stuffer, struct s2n_stuffer *out, uint32_t n);
extern int s2n_stuffer_read_uint8_hex(struct s2n_stuffer *stuffer, uint8_t *u);
extern int s2n_stuffer_read_uint16_hex(struct s2n_stuffer *stuffer, uint16_t *u);
extern int s2n_stuffer_read_uint32_hex(struct s2n_stuffer *stuffer, uint32_t *u);
extern int s2n_stuffer_read_uint64_hex(struct s2n_stuffer *stuffer, uint64_t *u);

extern int s2n_stuffer_write_hex(struct s2n_stuffer *stuffer, struct s2n_stuffer *in, uint32_t n);
extern int s2n_stuffer_write_uint8_hex(struct s2n_stuffer *stuffer, uint8_t u);
extern int s2n_stuffer_write_uint16_hex(struct s2n_stuffer *stuffer, uint16_t u);
extern int s2n_stuffer_write_uint32_hex(struct s2n_stuffer *stuffer, uint32_t u);
extern int s2n_stuffer_write_uint64_hex(struct s2n_stuffer *stuffer, uint64_t u);
extern int s2n_stuffer_alloc_ro_from_hex_string(struct s2n_stuffer *stuffer, const char *str);

void s2n_print_connection(struct s2n_connection *conn, const char *marker);

#define S2N_MAX_TEST_PEM_SIZE 4096

/* These paths assume that the unit tests are run from inside the unit/ directory.
 * Absolute paths will be needed if test directories go to deeper levels.
 */
#define S2N_RSA_2048_PKCS8_CERT_CHAIN   "../pems/rsa_2048_pkcs8_cert.pem"
#define S2N_RSA_2048_PKCS1_CERT_CHAIN   "../pems/rsa_2048_pkcs1_cert.pem"
#define S2N_RSA_2048_PKCS1_CERT_CHAIN_CORRUPT   "../pems/rsa_2048_pkcs1_cert_corrupted.pem"

#define S2N_RSA_2048_PKCS1_LEAF_CERT    "../pems/rsa_2048_pkcs1_leaf.pem"
#define S2N_ECDSA_P384_PKCS1_CERT_CHAIN "../pems/ecdsa_p384_pkcs1_cert.pem"
#define S2N_RSA_CERT_CHAIN_CRLF         "../pems/rsa_2048_pkcs1_cert_crlf.pem"
#define S2N_RSA_KEY_CRLF                "../pems/rsa_2048_pkcs1_key_crlf.pem"
#define S2N_ECDSA_P384_PKCS1_KEY        "../pems/ecdsa_p384_pkcs1_key.pem"
#define S2N_RSA_2048_PKCS1_KEY          "../pems/rsa_2048_pkcs1_key.pem"
#define S2N_RSA_2048_PKCS8_KEY          "../pems/rsa_2048_pkcs8_key.pem"

/* "Strangely" formatted PEMs that should still parse successfully */
#define S2N_LEAF_WHITESPACE_CERT_CHAIN         "../pems/rsa_2048_leaf_whitespace_cert.pem"
#define S2N_INTERMEDIATE_WHITESPACE_CERT_CHAIN "../pems/rsa_2048_intermediate_whitespace_cert.pem"
#define S2N_ROOT_WHITESPACE_CERT_CHAIN         "../pems/rsa_2048_root_whitespace_cert.pem"
#define S2N_TRAILING_WHITESPACE_CERT_CHAIN     "../pems/rsa_2048_trailing_whitespace_cert.pem"
#define S2N_LEADING_COMMENT_TEXT_CERT_CHAIN    "../pems/rsa_2048_leading_comment_text_cert.pem"

/* Illegally formatted PEMs */
#define S2N_INVALID_HEADER_CERT_CHAIN   "../pems/rsa_2048_invalid_header_cert.pem"
#define S2N_INVALID_TRAILER_CERT_CHAIN  "../pems/rsa_2048_invalid_trailer_cert.pem"
#define S2N_UNKNOWN_KEYWORD_CERT_CHAIN  "../pems/rsa_2048_unknown_keyword_cert.pem"
#define S2N_INVALID_HEADER_KEY          "../pems/rsa_2048_invalid_header_key.pem"
#define S2N_INVALID_TRAILER_KEY         "../pems/rsa_2048_invalid_trailer_key.pem"
#define S2N_UNKNOWN_KEYWORD_KEY         "../pems/rsa_2048_unknown_keyword_key.pem"

#define S2N_DHPARAMS_2048 "../pems/dhparams_2048.pem"

#define S2N_DEFAULT_TEST_CERT_CHAIN  S2N_RSA_2048_PKCS1_CERT_CHAIN
#define S2N_DEFAULT_TEST_PRIVATE_KEY S2N_RSA_2048_PKCS1_KEY

#define S2N_DEFAULT_TEST_DHPARAMS S2N_DHPARAMS_2048

/* Read a cert given a path into pem_out */
int s2n_read_test_pem(const char *pem_path, char *pem_out, long int max_size);
int s2n_read_test_file(const char *path, char *out, long int max_size, long int *file_size);

