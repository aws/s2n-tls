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

int s2n_connection_set_io_stuffers(struct s2n_stuffer *input, struct s2n_stuffer *output, struct s2n_connection *conn);

struct s2n_test_piped_io {
    int client_read;
    int client_write;
    int server_read;
    int server_write;
};
int s2n_piped_io_init(struct s2n_test_piped_io *piped_io);
int s2n_piped_io_init_non_blocking(struct s2n_test_piped_io *piped_io);
int s2n_piped_io_close(struct s2n_test_piped_io *piped_io);
int s2n_piped_io_close_one_end(struct s2n_test_piped_io *piped_io, int mode_to_close);

int s2n_connection_set_piped_io(struct s2n_connection *conn, struct s2n_test_piped_io* piped_io);
int s2n_connections_set_piped_io(struct s2n_connection *client, struct s2n_connection *server, struct s2n_test_piped_io* piped_io);

int s2n_fd_set_blocking(int fd);
int s2n_fd_set_non_blocking(int fd);

int s2n_set_connection_hello_retry_flags(struct s2n_connection *conn);
int s2n_set_connection_server_hello_flags(struct s2n_connection *conn);
int s2n_connection_allow_all_response_extensions(struct s2n_connection *conn);

int s2n_unsafe_set_drbg_seed(const struct s2n_blob *seed);

#define S2N_MAX_TEST_PEM_SIZE 4096

/* These paths assume that the unit tests are run from inside the unit/ directory.
 * Absolute paths will be needed if test directories go to deeper levels.
 */
#define S2N_RSA_2048_PKCS8_CERT_CHAIN   "../pems/rsa_2048_pkcs8_cert.pem"
#define S2N_RSA_2048_PKCS1_CERT_CHAIN   "../pems/rsa_2048_pkcs1_cert.pem"

#define S2N_RSA_2048_PKCS1_LEAF_CERT    "../pems/rsa_2048_pkcs1_leaf.pem"
#define S2N_ECDSA_P256_PKCS1_CERT_CHAIN "../pems/ecdsa_p256_pkcs1_cert.pem"
#define S2N_ECDSA_P384_PKCS1_CERT_CHAIN "../pems/ecdsa_p384_pkcs1_cert.pem"
#define S2N_RSA_CERT_CHAIN_CRLF         "../pems/rsa_2048_pkcs1_cert_crlf.pem"
#define S2N_RSA_KEY_CRLF                "../pems/rsa_2048_pkcs1_key_crlf.pem"
#define S2N_ECDSA_P256_PKCS1_KEY        "../pems/ecdsa_p256_pkcs1_key.pem"
#define S2N_ECDSA_P384_PKCS1_KEY        "../pems/ecdsa_p384_pkcs1_key.pem"
#define S2N_RSA_2048_PKCS1_KEY          "../pems/rsa_2048_pkcs1_key.pem"
#define S2N_RSA_2048_PKCS8_KEY          "../pems/rsa_2048_pkcs8_key.pem"

#define S2N_RSA_PSS_2048_SHA256_CA_KEY         "../pems/rsa_pss_2048_sha256_CA_key.pem"
#define S2N_RSA_PSS_2048_SHA256_CA_CERT        "../pems/rsa_pss_2048_sha256_CA_cert.pem"
#define S2N_RSA_PSS_2048_SHA256_LEAF_KEY       "../pems/rsa_pss_2048_sha256_leaf_key.pem"
#define S2N_RSA_PSS_2048_SHA256_LEAF_CERT      "../pems/rsa_pss_2048_sha256_leaf_cert.pem"

#define S2N_RSA_2048_SHA256_CLIENT_CERT "../pems/rsa_2048_sha256_client_cert.pem"

#define S2N_RSA_2048_SHA256_NO_DNS_SANS_CERT "../pems/rsa_2048_sha256_no_dns_sans_cert.pem"
#define S2N_RSA_2048_SHA256_WILDCARD_CERT    "../pems/rsa_2048_sha256_wildcard_cert.pem"

#define S2N_RSA_2048_SHA256_URI_SANS_CERT "../pems/rsa_2048_sha256_uri_sans_cert.pem"

/* "Strangely" formatted PEMs that should still parse successfully */
#define S2N_LEAF_WHITESPACE_CERT_CHAIN         "../pems/rsa_2048_leaf_whitespace_cert.pem"
#define S2N_INTERMEDIATE_WHITESPACE_CERT_CHAIN "../pems/rsa_2048_intermediate_whitespace_cert.pem"
#define S2N_ROOT_WHITESPACE_CERT_CHAIN         "../pems/rsa_2048_root_whitespace_cert.pem"
#define S2N_TRAILING_WHITESPACE_CERT_CHAIN     "../pems/rsa_2048_trailing_whitespace_cert.pem"
#define S2N_LEADING_COMMENT_TEXT_CERT_CHAIN    "../pems/rsa_2048_leading_comment_text_cert.pem"
#define S2N_LONG_BASE64_LINES_CERT_CHAIN       "../pems/rsa_2048_varying_base64_len_cert.pem"
/* Missing line endings between PEM encapsulation boundaries */
#define S2N_MISSING_LINE_ENDINGS_CERT_CHAIN    "../pems/rsa_2048_missing_line_endings_cert.pem"

/* Illegally formatted PEMs */
#define S2N_INVALID_HEADER_CERT_CHAIN   "../pems/rsa_2048_invalid_header_cert.pem"
#define S2N_INVALID_TRAILER_CERT_CHAIN  "../pems/rsa_2048_invalid_trailer_cert.pem"
#define S2N_UNKNOWN_KEYWORD_CERT_CHAIN  "../pems/rsa_2048_unknown_keyword_cert.pem"
#define S2N_INVALID_HEADER_KEY          "../pems/rsa_2048_invalid_header_key.pem"
#define S2N_INVALID_TRAILER_KEY         "../pems/rsa_2048_invalid_trailer_key.pem"
#define S2N_UNKNOWN_KEYWORD_KEY         "../pems/rsa_2048_unknown_keyword_key.pem"
#define S2N_WEIRD_DASHES_CERT_CHAIN     "../pems/rsa_2048_weird_dashes_cert.pem"
#define S2N_NO_DASHES_CERT_CHAIN        "../pems/rsa_2048_no_dashes_cert.pem"

/* OCSP Stapled Response Testing files */
#define S2N_OCSP_SERVER_CERT                   "../pems/ocsp/server_cert.pem"
#define S2N_OCSP_SERVER_KEY                    "../pems/ocsp/server_key.pem"
#define S2N_OCSP_CA_CERT                       "../pems/ocsp/ca_cert.pem"
#define S2N_OCSP_CA_KEY                        "../pems/ocsp/ca_key.pem"
#define S2N_OCSP_RESPONSE_DER                  "../pems/ocsp/ocsp_response.der"
#define S2N_OCSP_RESPONSE_NO_NEXT_UPDATE_DER   "../pems/ocsp/ocsp_response_no_next_update.der"
#define S2N_OCSP_RESPONSE_CERT                 "../pems/ocsp/ocsp_cert.pem"

#define S2N_ALLIGATOR_SAN_CERT                 "../pems/sni/alligator_cert.pem"
#define S2N_ALLIGATOR_SAN_KEY                  "../pems/sni/alligator_key.pem"

#define S2N_DHPARAMS_2048 "../pems/dhparams_2048.pem"

#define S2N_DEFAULT_TEST_CERT_CHAIN  S2N_RSA_2048_PKCS1_CERT_CHAIN
#define S2N_DEFAULT_TEST_PRIVATE_KEY S2N_RSA_2048_PKCS1_KEY

#define S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN  S2N_ECDSA_P384_PKCS1_CERT_CHAIN
#define S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY S2N_ECDSA_P384_PKCS1_KEY

#define S2N_DEFAULT_TEST_DHPARAMS S2N_DHPARAMS_2048

/* Read a cert given a path into pem_out */
int s2n_read_test_pem(const char *pem_path, char *pem_out, long int max_size);
int s2n_test_cert_chain_and_key_new(struct s2n_cert_chain_and_key **chain_and_key,
        const char *cert_chain_file, const char *private_key_file);

int s2n_negotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn);
int s2n_shutdown_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn);

int s2n_test_kem_with_kat(const struct s2n_kem *kem, const char *kat_file);
int s2n_test_hybrid_ecdhe_kem_with_kat(const struct s2n_kem *kem, struct s2n_cipher_suite *cipher_suite,
        const char *cipher_pref_version, const char * kat_file_name, uint32_t server_key_message_length,
        uint32_t client_key_message_length);

/* Expects 2 s2n_blobs to be equal (same size and contents) */
#define S2N_BLOB_EXPECT_EQUAL( blob1, blob2 ) do {              \
    EXPECT_EQUAL(blob1.size, blob2.size);                       \
    EXPECT_BYTEARRAY_EQUAL(blob1.data, blob2.data, blob1.size); \
} while (0)

/* Expects data of type in stuffer, where type is uint32, uint64 etc.. */
#define S2N_STUFFER_READ_EXPECT_EQUAL( stuffer, expected, type ) do { \
    type##_t value;                                                   \
    EXPECT_SUCCESS(s2n_stuffer_read_##type(stuffer, &value));         \
    EXPECT_EQUAL(value, expected);                                    \
} while (0)

/* Expects written length in stuffer */
#define S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL( stuffer, bytes ) do { \
    EXPECT_SUCCESS(s2n_stuffer_skip_read(stuffer, bytes));      \
    EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);       \
} while (0)

int s2n_public_ecc_keys_are_equal(struct s2n_ecc_evp_params *params_1, struct s2n_ecc_evp_params *params_2);
