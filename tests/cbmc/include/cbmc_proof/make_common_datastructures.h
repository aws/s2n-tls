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

#include <cbmc_proof/cbmc_utils.h>

#include "api/s2n.h"
#include "crypto/s2n_certificate.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_evp.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_hmac.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_array.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_map_internal.h"
#include "utils/s2n_safety_macros.h"
#include "utils/s2n_set.h"
#include "utils/s2n_socket.h"

/*
 * Checks whether s2n_blob is bounded by max_size.
 */
bool s2n_blob_is_bounded(const struct s2n_blob *blob, const size_t max_size);

/*
 * Checks whether s2n_stuffer is bounded by max_size.
 */
bool s2n_stuffer_is_bounded(const struct s2n_stuffer *stuffer, const size_t max_size);

/*
 * Populates the fields of a pre-allocated s2n_blob for CBMC proofs.
 */
void cbmc_populate_s2n_blob(struct s2n_blob *blob);

/*
 * Properly allocates s2n_blob for CBMC proofs.
 */
struct s2n_blob *cbmc_allocate_s2n_blob();

/*
 * Populates the fields of a pre-allocated s2n_stuffer for CBMC proofs.
 */
void cbmc_populate_s2n_stuffer(struct s2n_stuffer *stuffer);

/*
 * Properly allocates s2n_stuffer for CBMC proofs.
 */
struct s2n_stuffer *cbmc_allocate_s2n_stuffer();

/*
 * Ensures a valid const string is allocated,
 * with as much nondet as possible, len < max_size.
 */
const char *ensure_c_str_is_allocated(size_t max_size);

/*
 * Nondeterministically return a valid-allocated const string or NULL,
 * with as much nondet as possible, len < max_size.
 */
const char *nondet_c_str_is_allocated(size_t max_size);

/*
 * Populates the fields of a pre-allocated s2n_stuffer_reservation for CBMC proofs.
 */
void cbmc_populate_s2n_stuffer_reservation(struct s2n_stuffer_reservation *reservation);

/*
 * Properly allocates s2n_stuffer_reservation for CBMC proofs.
 */
struct s2n_stuffer_reservation *cbmc_allocate_s2n_stuffer_reservation();

/*
 * Checks whether s2n_array is bounded by max_len and max_element_size.
 */
bool s2n_array_is_bounded(const struct s2n_array *array, const size_t max_len, const size_t max_element_size);

/*
 * Populates the fields of a pre-allocated s2n_array for CBMC proofs.
 */
void cbmc_populate_s2n_array(struct s2n_array *array);

/*
 * Properly allocates s2n_array for CBMC proofs.
 */
struct s2n_array *cbmc_allocate_s2n_array();

/*
 * Checks whether s2n_set is bounded by max_len and max_element_size.
 */
bool s2n_set_is_bounded(const struct s2n_set *set, const size_t max_len, const size_t max_element_size);

/*
 * Populates the fields of a pre-allocated s2n_set for CBMC proofs.
 */
void cbmc_populate_s2n_set(struct s2n_set *set);

/*
 * Properly allocates s2n_set for CBMC proofs.
 */
struct s2n_set *cbmc_allocate_s2n_set();

/*
 * Populates the fields of a pre-allocated s2n_dh_params for CBMC proofs.
 */
void cbmc_populate_s2n_dh_params(struct s2n_dh_params *s2n_dh_params);

/*
 * Properly allocates s2n_dh_params for CBMC proofs.
 */
struct s2n_dh_params *cbmc_allocate_dh_params();

/*
 * Populates the fields of a pre-allocated BIGNUM for CBMC proofs.
 */
void cbmc_populate_BIGNUM(BIGNUM *bignum);

/*
 * Properly allocates BIGNUM for CBMC proofs.
 */
BIGNUM *cbmc_allocate_BIGNUM();

/*
 * Populates the fields of a pre-allocated EC_GROUP for CBMC proofs.
 */
void cbmc_populate_EC_GROUP(EC_GROUP *ec_group);

/*
 * Properly allocates EC_GROUP for CBMC proofs.
 */
EC_GROUP *cbmc_allocate_EC_GROUP();

/*
 * Populates the fields of a pre-allocated EC_KEY for CBMC proofs.
 */
void cbmc_populate_EC_KEY(EC_KEY *ec_key);

/*
 * Properly allocates EC_KEY for CBMC proofs.
 */
EC_KEY *cbmc_allocate_EC_KEY();

/*
 * Populates the fields of a pre-allocated EVP_PKEY for CBMC proofs.
 */
void cbmc_populate_EVP_PKEY(EVP_PKEY *evp_pkey);

/*
 * Properly allocates EVP_PKEY for CBMC proofs.
 */
EVP_PKEY *cbmc_allocate_EVP_PKEY();

/*
 * Populates the fields of a pre-allocated EVP_PKEY_CTX for CBMC proofs.
 */
void cbmc_populate_EVP_PKEY_CTX(EVP_PKEY_CTX *evp_pkey_ctx);

/*
 * Properly allocates EVP_PKEY_CTX for CBMC proofs.
 */
EVP_PKEY_CTX *cbmc_allocate_EVP_PKEY_CTX();

/*
 * Populates the fields of a pre-allocated EVP_MD_CTX for CBMC proofs.
 */
void cbmc_populate_EVP_MD_CTX(EVP_MD_CTX *ctx);

/*
 * Properly allocates EVP_MD_CTX for CBMC proofs.
 */
EVP_MD_CTX* cbmc_allocate_EVP_MD_CTX();

/*
 * Populates the fields of a pre-allocated s2n_evp_digest for CBMC proofs.
 */
void cbmc_populate_s2n_evp_digest(struct s2n_evp_digest *evp_digest);

/*
 * Properly allocates s2n_evp_digest for CBMC proofs.
 */
struct s2n_evp_digest* cbmc_allocate_s2n_evp_digest();

/*
 * Populates the fields of a pre-allocated s2n_evp_digest for CBMC proofs.
 */
void cbmc_populate_s2n_evp_hmac_state(struct s2n_evp_hmac_state *evp_hmac_state);

/*
 * Properly allocates s2n_evp_hmac_state for CBMC proofs.
 */
struct s2n_evp_hmac_state *cbmc_allocate_s2n_evp_hmac_state();

/*
 * Populates the fields of a pre-allocated s2n_hash_state for CBMC proofs.
 */
void cbmc_populate_s2n_hash_state(struct s2n_hash_state *state);

/*
 * Properly allocates s2n_hash_state for CBMC proofs.
 */
struct s2n_hash_state *cbmc_allocate_s2n_hash_state();

/*
 * Populates the fields of a pre-allocated s2n_hmac_state for CBMC proofs.
 */
void cbmc_populate_s2n_hmac_state(struct s2n_hmac_state *state);

/*
 * Properly allocates s2n_hmac_state for CBMC proofs.
 */
struct s2n_hmac_state* cbmc_allocate_s2n_hmac_state();

/*
 * Populates the fields of a pre-allocated s2n_hmac_evp_backup for CBMC proofs.
 */
void cbmc_populate_s2n_hmac_evp_backup(struct s2n_hmac_evp_backup *backup);

/*
 * Properly allocates s2n_hmac_state for CBMC proofs.
 */
struct s2n_hmac_evp_backup* cbmc_allocate_s2n_hmac_evp_backup();

/*
 * Populates the fields of a pre-allocated s2n_map for CBMC proofs.
 */
void cbmc_populate_s2n_map(struct s2n_map *s2n_map);

/*
 * Properly allocates s2n_map for CBMC proofs.
 */
struct s2n_map *cbmc_allocate_s2n_map();

/*
 * Properly allocates s2n_cipher_preferences for CBMC proofs.
 */
struct s2n_cipher_preferences *cbmc_allocate_s2n_cipher_preferences();

/*
 * Properly allocates s2n_kem_preferences for CBMC proofs.
 */
struct s2n_kem_preferences *cbmc_allocate_s2n_kem_preferences();

/*
 * Properly allocates s2n_signature_preferences for CBMC proofs.
 */
struct s2n_signature_preferences *cbmc_allocate_s2n_signature_preferences();

/*
 * Properly allocates s2n_ecc_preferences for CBMC proofs.
 */
struct s2n_ecc_preferences *cbmc_allocate_s2n_ecc_preferences();

/*
 * Properly allocates s2n_security_policy for CBMC proofs.
 */
struct s2n_security_policy *cbmc_allocate_s2n_security_policy();

/*
 * Properly allocates X509_STORE for CBMC proofs.
 */
X509_STORE *cbmc_allocate_X509_STORE();

/*
 * Populates the fields of a pre-allocated s2n_x509_trust_store for CBMC proofs.
 */
void cbmc_populate_s2n_x509_trust_store(struct s2n_x509_trust_store *s2n_x509_trust_store);

/*
 * Properly allocates s2n_config for CBMC proofs.
 */
struct s2n_config *cbmc_allocate_s2n_config();

/*
 * Populates the fields of a pre-allocated s2n_rsa_key for CBMC proofs.
 */
void cbmc_populate_s2n_rsa_key(struct s2n_rsa_key *s2n_rsa_key);

/*
 * Populates the fields of a pre-allocated s2n_ecdsa_key for CBMC proofs.
 */
void cbmc_populate_s2n_ecdsa_key(struct s2n_ecdsa_key *s2n_ecdsa_key);

/*
 * Populates the fields of a pre-allocated s2n_pkey for CBMC proofs.
 */
void cbmc_populate_s2n_pkey(struct s2n_pkey *s2n_pkey);

/*
 * Properly allocates s2n_pkey for CBMC proofs.
 */
struct s2n_pkey *cbmc_allocate_s2n_pkey();

/*
 * Populates the fields of a pre-allocated s2n_ecc_evp_params for CBMC proofs.
 */
void cbmc_populate_s2n_ecc_evp_params(struct s2n_ecc_evp_params *s2n_ecc_evp_params);

/*
 * Properly allocates s2n_ecc_named_curve for CBMC proofs.
 */
struct s2n_ecc_named_curve *cbmc_allocate_s2n_ecc_named_curve();

/*
 * Properly allocates s2n_kem for CBMC proofs.
 */
struct s2n_kem *cbmc_allocate_s2n_kem();

/*
 * Properly allocates s2n_kem_group for CBMC proofs.
 */
struct s2n_kem_group *cbmc_allocate_s2n_kem_group();

/*
 * Populates the fields of a pre-allocated s2n_kem_params for CBMC proofs.
 */
void cbmc_populate_s2n_kem_params(struct s2n_kem_params *s2n_kem_params);

/*
 * Populates the fields of a pre-allocated s2n_kem_group_params for CBMC proofs.
 */
void cbmc_populate_s2n_kem_group_params(struct s2n_kem_group_params *s2n_kem_group_params);

/*
 * Properly allocates s2n_kem_group_params for CBMC proofs.
 */
struct s2n_kem_group_params *cbmc_allocate_s2n_kem_group_params();

/*
 * Populates the fields of a pre-allocated s2n_signature_scheme for CBMC proofs.
 */
void cbmc_populate_s2n_signature_scheme(struct s2n_signature_scheme *s2n_signature_scheme);

/*
 * Properly allocates s2n_kex for CBMC proofs.
 */
struct s2n_kex *cbmc_allocate_s2n_kex();

/*
 * Properly allocates s2n_cipher for CBMC proofs.
 */
struct s2n_cipher *cbmc_allocate_s2n_cipher();

/*
 * Properly allocates s2n_record_algorithm for CBMC proofs.
 */
struct s2n_record_algorithm *cbmc_allocate_s2n_record_algorithm();

/*
 * Properly allocates s2n_cipher_suite for CBMC proofs.
 */
struct s2n_cipher_suite *cbmc_allocate_s2n_cipher_suite();

/*
 * Populates the fields of a pre-allocated s2n_session_key for CBMC proofs.
 */
void cbmc_populate_s2n_session_key(struct s2n_session_key *s2n_session_key);

/*
 * Populates the fields of a pre-allocated s2n_crypto_parameters for CBMC proofs.
 */
void cbmc_populate_s2n_crypto_parameters(struct s2n_crypto_parameters *s2n_crypto_parameters);

/*
 * Properly allocates s2n_crypto_parameters for CBMC proofs.
 */
struct s2n_crypto_parameters *cbmc_allocate_s2n_crypto_parameters();

/*
 * Populates the fields of a pre-allocated s2n_cert for CBMC proofs.
 */
void cbmc_populate_s2n_cert(struct s2n_cert *s2n_cert);

/*
 * Properly allocates s2n_cert for CBMC proofs.
 */
struct s2n_cert *cbmc_allocate_s2n_cert();

/*
 * Populates the fields of a pre-allocated s2n_cert_chain for CBMC proofs.
 */
void cbmc_populate_s2n_cert_chain(struct s2n_cert_chain *s2n_cert_chain);

/*
 * Properly allocates s2n_cert_chain for CBMC proofs.
 */
struct s2n_cert_chain *cbmc_allocate_s2n_cert_chain();

/*
 * Populates the fields of a pre-allocated s2n_cert_chain_and_key for CBMC proofs.
 */
void cbmc_populate_s2n_cert_chain_and_key(struct s2n_cert_chain_and_key *s2n_cert_chain_and_key);

/*
 * Populates the fields of a pre-allocated s2n_handshake_parameters for CBMC proofs.
 */
void cbmc_populate_s2n_handshake_parameters(struct s2n_handshake_parameters *s2n_handshake_parameters);

/*
 * Populates the fields of a pre-allocated s2n_early_data_config for CBMC proofs.
 */
void cbmc_populate_s2n_early_data_config(struct s2n_early_data_config *s2n_early_data_config);

/*
 * Populates the fields of a pre-allocated s2n_psk for CBMC proofs.
 */
void cbmc_populate_s2n_psk(struct s2n_psk *s2n_psk);

/*
 * Properly allocates s2n_psk for CBMC proofs.
 */
struct s2n_psk *cbmc_allocate_s2n_psk();

/*
 * Populates the fields of a pre-allocated s2n_psk_parameters for CBMC proofs.
 */
void cbmc_populate_s2n_psk_parameters(struct s2n_psk_parameters *s2n_psk_parameters);

/*
 * Populates the fields of a pre-allocated s2n_prf_working_space for CBMC proofs.
 */
void cbmc_populate_s2n_prf_working_space(struct s2n_prf_working_space *s2n_prf_working_space);

/*
 * Populates the fields of a pre-allocated s2n_handshake for CBMC proofs.
 */
void cbmc_populate_s2n_handshake(struct s2n_handshake *s2n_handshake);

/*
 * Populates the fields of a pre-allocated s2n_client_hello for CBMC proofs.
 */
void cbmc_populate_s2n_client_hello(struct s2n_client_hello *s2n_client_hello);

/*
 * Populates the fields of a pre-allocated s2n_x509_validator for CBMC proofs.
 */
void cbmc_populate_s2n_x509_validator(struct s2n_x509_validator *s2n_x509_validator);

/*
 * Populates the fields of a pre-allocated s2n_ticket_fields for CBMC proofs.
 */
void cbmc_populate_s2n_ticket_fields(struct s2n_ticket_fields *s2n_ticket_fields);

/*
 * Populates the fields of a pre-allocated s2n_connection for CBMC proofs.
 */
void cbmc_populate_s2n_connection(struct s2n_connection *s2n_connection);

/*
 * Properly allocates s2n_connection for CBMC proofs.
 */
struct s2n_connection *cbmc_allocate_s2n_connection();

struct s2n_socket_read_io_context *cbmc_allocate_s2n_socket_read_io_context();

struct s2n_socket_write_io_context *cbmc_allocate_s2n_socket_write_io_context();
