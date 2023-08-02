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

#include <cbmc_proof/make_common_datastructures.h>
#include <utils/s2n_safety_macros.h>

bool s2n_blob_is_bounded(const struct s2n_blob *blob, const size_t max_size) { return (blob->size <= max_size); }

bool s2n_stuffer_is_bounded(const struct s2n_stuffer *stuffer, const size_t max_size)
{
    return (stuffer->blob.size <= max_size);
}

void cbmc_populate_s2n_blob(struct s2n_blob *blob)
{
    CBMC_ENSURE_REF(blob);
    if (blob->growable) {
        blob->data = (blob->allocated == 0) ? NULL : malloc(blob->allocated);
    } else {
        blob->data = (blob->size == 0) ? NULL : malloc(blob->size);
    }
}

struct s2n_blob *cbmc_allocate_s2n_blob()
{
    struct s2n_blob *blob = malloc(sizeof(*blob));
    cbmc_populate_s2n_blob(blob);
    return blob;
}

void cbmc_populate_s2n_stuffer(struct s2n_stuffer *stuffer)
{
    CBMC_ENSURE_REF(stuffer);
    cbmc_populate_s2n_blob(&stuffer->blob);
}

struct s2n_stuffer *cbmc_allocate_s2n_stuffer()
{
    struct s2n_stuffer *stuffer = malloc(sizeof(*stuffer));
    cbmc_populate_s2n_stuffer(stuffer);
    return stuffer;
}

const char *ensure_c_str_is_allocated(size_t max_size)
{
    size_t cap;
    __CPROVER_assume(cap > 0 && cap <= max_size);
    const char *str = malloc(cap);
    /* Ensure that its a valid c string. Since all bytes are nondeterminstic, the actual
     * string length is 0..str_cap
     */
    __CPROVER_assume(IMPLIES(str != NULL, str[ cap - 1 ] == '\0'));
    return str;
}

const char *nondet_c_str_is_allocated(size_t max_size)
{
    size_t cap;
    __CPROVER_assume(cap > 0 && cap <= max_size);
    const char *str = malloc(cap);
    /* Ensure that its a valid c string. Since all bytes are nondeterminstic, the actual
     * string length is 0..str_cap
     */
    __CPROVER_assume(IMPLIES(str != NULL, str[ cap - 1 ] == 0));
    return str;
}

void cbmc_populate_s2n_stuffer_reservation(struct s2n_stuffer_reservation *reservation)
{
    CBMC_ENSURE_REF(reservation);
    reservation->stuffer = cbmc_allocate_s2n_stuffer();
}

struct s2n_stuffer_reservation *cbmc_allocate_s2n_stuffer_reservation()
{
    struct s2n_stuffer_reservation *reservation = malloc(sizeof(*reservation));
    cbmc_populate_s2n_stuffer_reservation(reservation);
    return reservation;
}

bool s2n_array_is_bounded(const struct s2n_array *array, const size_t max_len, const size_t max_element_size)
{
    return (array->len <= max_len) && (array->element_size <= max_element_size);
}

void cbmc_populate_s2n_array(struct s2n_array *array)
{
    CBMC_ENSURE_REF(array);
    cbmc_populate_s2n_blob(&array->mem);
}

struct s2n_array *cbmc_allocate_s2n_array()
{
    struct s2n_array *array = malloc(sizeof(*array));
    cbmc_populate_s2n_array(array);
    return array;
}

bool s2n_set_is_bounded(const struct s2n_set *set, const size_t max_len, const size_t max_element_size)
{
    return s2n_array_is_bounded(set->data, max_len, max_element_size);
}

static int nondet_comparator(const void *a, const void *b)
{
    __CPROVER_assert(a != NULL, "a is not NULL");
    __CPROVER_assert(b != NULL, "b is not NULL");
    return nondet_int();
}

void cbmc_populate_s2n_set(struct s2n_set *set)
{
    CBMC_ENSURE_REF(set);
    set->data       = cbmc_allocate_s2n_array();
    set->comparator = nondet_comparator;
}

struct s2n_set *cbmc_allocate_s2n_set()
{
    struct s2n_set *set = malloc(sizeof(*set));
    cbmc_populate_s2n_set(set);
    return set;
}

void cbmc_populate_s2n_dh_params(struct s2n_dh_params *s2n_dh_params)
{
    CBMC_ENSURE_REF(s2n_dh_params);
    s2n_dh_params->dh = DH_new();
}

struct s2n_dh_params *cbmc_allocate_dh_params()
{
    struct s2n_dh_params *dh_params = malloc(sizeof(*dh_params));
    cbmc_populate_s2n_dh_params(dh_params);
    return dh_params;
}

void cbmc_populate_BIGNUM(BIGNUM *bignum)
{
    CBMC_ENSURE_REF(bignum);
    bignum->d = malloc(sizeof(*(bignum->d)));
}

BIGNUM *cbmc_allocate_BIGNUM()
{
    BIGNUM *bignum = malloc(sizeof(*bignum));
    cbmc_populate_BIGNUM(bignum);
    return bignum;
}

void cbmc_populate_EC_GROUP(EC_GROUP *ec_group)
{
    CBMC_ENSURE_REF(ec_group);
    ec_group->order = cbmc_allocate_BIGNUM();
}

EC_GROUP *cbmc_allocate_EC_GROUP()
{
    EC_GROUP *ec_group = malloc(sizeof(*ec_group));
    cbmc_populate_EC_GROUP(ec_group);
    return ec_group;
}

void cbmc_populate_EC_KEY(EC_KEY *ec_key)
{
    CBMC_ENSURE_REF(ec_key);
    ec_key->group    = cbmc_allocate_EC_GROUP();
    ec_key->priv_key = cbmc_allocate_BIGNUM();
}

EC_KEY *cbmc_allocate_EC_KEY()
{
    EC_KEY *ec_key = malloc(sizeof(*ec_key));
    cbmc_populate_EC_KEY(ec_key);
    return ec_key;
}

void cbmc_populate_EVP_PKEY(EVP_PKEY *evp_pkey)
{
    CBMC_ENSURE_REF(evp_pkey);
    evp_pkey->ec_key = cbmc_allocate_EC_KEY();
}

EVP_PKEY *cbmc_allocate_EVP_PKEY()
{
    EVP_PKEY *evp_pkey = malloc(sizeof(*evp_pkey));
    cbmc_populate_EVP_PKEY(evp_pkey);
    return evp_pkey;
}

void cbmc_populate_EVP_PKEY_CTX(EVP_PKEY_CTX *evp_pkey_ctx)
{
    CBMC_ENSURE_REF(evp_pkey_ctx);
    evp_pkey_ctx->pkey = cbmc_allocate_EVP_PKEY();
}

EVP_PKEY_CTX *cbmc_allocate_EVP_PKEY_CTX()
{
    EVP_PKEY_CTX *evp_pkey_ctx = malloc(sizeof(*evp_pkey_ctx));
    cbmc_populate_EVP_PKEY_CTX(evp_pkey_ctx);
    return evp_pkey_ctx;
}

void cbmc_populate_EVP_MD_CTX(EVP_MD_CTX *ctx)
{
    CBMC_ENSURE_REF(ctx);
    ctx->digest  = malloc(sizeof(*(ctx->digest)));
    ctx->md_data = malloc(EVP_MAX_MD_SIZE);
    ctx->pctx    = cbmc_allocate_EVP_PKEY_CTX();
}

EVP_MD_CTX *cbmc_allocate_EVP_MD_CTX()
{
    EVP_MD_CTX *ctx = malloc(sizeof(*ctx));
    cbmc_populate_EVP_MD_CTX(ctx);
    return ctx;
}

void cbmc_populate_s2n_evp_digest(struct s2n_evp_digest *evp_digest) {
    CBMC_ENSURE_REF(evp_digest);
    /* `evp_digest->md` is never allocated.
     * It is always initialized based on the hashing algorithm.
     * If required, this initialization should be done in the validation function.
     */
    evp_digest->ctx = cbmc_allocate_EVP_MD_CTX();
}

struct s2n_evp_digest* cbmc_allocate_s2n_evp_digest()
{
    struct s2n_evp_digest *evp_digest = malloc(sizeof(*evp_digest));
    cbmc_populate_s2n_evp_digest(evp_digest);
    return evp_digest;
}

void cbmc_populate_s2n_evp_hmac_state(struct s2n_evp_hmac_state *evp_hmac_state)
{
    CBMC_ENSURE_REF(evp_hmac_state);
    cbmc_populate_s2n_evp_digest(&(evp_hmac_state->evp_digest));
    if (s2n_libcrypto_is_awslc() || s2n_libcrypto_is_boringssl()) {
        evp_hmac_state->ctx.hmac_ctx = malloc(sizeof(*(evp_hmac_state->ctx.hmac_ctx)));
    } else {
        evp_hmac_state->ctx.evp_pkey = malloc(sizeof(*(evp_hmac_state->ctx.evp_pkey)));
    }
}

struct s2n_evp_hmac_state *cbmc_allocate_s2n_evp_hmac_state()
{
    struct s2n_evp_hmac_state *evp_hmac_state = malloc(sizeof(*evp_hmac_state));
    cbmc_populate_s2n_evp_hmac_state(evp_hmac_state);
    return evp_hmac_state;
}

void cbmc_populate_s2n_hash_state(struct s2n_hash_state* state)
{
    CBMC_ENSURE_REF(state);
    /* `state->hash_impl` is never allocated.
     * It is always initialized based on the hashing algorithm.
     * If required, this initialization should be done in the validation function.
     */
    cbmc_populate_s2n_evp_digest(&state->digest.high_level.evp);
    cbmc_populate_s2n_evp_digest(&state->digest.high_level.evp_md5_secondary);
}

struct s2n_hash_state* cbmc_allocate_s2n_hash_state()
{
    struct s2n_hash_state *state = malloc(sizeof(*state));
    cbmc_populate_s2n_hash_state(state);
    return state;
}

void cbmc_populate_s2n_hmac_state(struct s2n_hmac_state *state)
{
    CBMC_ENSURE_REF(state);
    cbmc_populate_s2n_hash_state(&state->inner);
    cbmc_populate_s2n_hash_state(&state->inner_just_key);
    cbmc_populate_s2n_hash_state(&state->outer);
    cbmc_populate_s2n_hash_state(&state->outer_just_key);
}

struct s2n_hmac_state* cbmc_allocate_s2n_hmac_state()
{
    struct s2n_hmac_state *state = malloc(sizeof(*state));
    cbmc_populate_s2n_hmac_state(state);
    return state;
}

void cbmc_populate_s2n_hmac_evp_backup(struct s2n_hmac_evp_backup *backup)
{
    CBMC_ENSURE_REF(backup);
    cbmc_populate_s2n_evp_digest(&backup->inner.evp);
    cbmc_populate_s2n_evp_digest(&backup->inner.evp_md5_secondary);
    cbmc_populate_s2n_evp_digest(&backup->inner_just_key.evp);
    cbmc_populate_s2n_evp_digest(&backup->inner_just_key.evp_md5_secondary);
    cbmc_populate_s2n_evp_digest(&backup->outer.evp);
    cbmc_populate_s2n_evp_digest(&backup->outer.evp_md5_secondary);
    cbmc_populate_s2n_evp_digest(&backup->outer_just_key.evp);
    cbmc_populate_s2n_evp_digest(&backup->outer_just_key.evp_md5_secondary);
}

struct s2n_hmac_evp_backup* cbmc_allocate_s2n_hmac_evp_backup()
{
    struct s2n_hmac_evp_backup *backup = malloc(sizeof(*backup));
    cbmc_populate_s2n_hmac_evp_backup(backup);
    return backup;
}

void cbmc_populate_s2n_map(struct s2n_map *s2n_map)
{
    CBMC_ENSURE_REF(s2n_map);
    s2n_map->table = malloc(sizeof(*(s2n_map->table)));
    if (s2n_map->table != NULL) {
        cbmc_populate_s2n_blob(&(s2n_map->table->key));
        cbmc_populate_s2n_blob(&(s2n_map->table->value));
    }
}

struct s2n_map *cbmc_allocate_s2n_map()
{
    struct s2n_map *s2n_map = malloc(sizeof(*s2n_map));
    cbmc_populate_s2n_map(s2n_map);
    return s2n_map;
}

struct s2n_cipher_preferences *cbmc_allocate_s2n_cipher_preferences()
{
    struct s2n_cipher_preferences *s2n_cipher_preferences = malloc(sizeof(*s2n_cipher_preferences));
    return s2n_cipher_preferences;
}

struct s2n_kem_preferences *cbmc_allocate_s2n_kem_preferences()
{
    struct s2n_kem_preferences *s2n_kem_preferences = malloc(sizeof(*s2n_kem_preferences));
    return s2n_kem_preferences;
}

struct s2n_signature_preferences *cbmc_allocate_s2n_signature_preferences()
{
    struct s2n_signature_preferences *s2n_signature_preferences = malloc(sizeof(*s2n_signature_preferences));
    return s2n_signature_preferences;
}

struct s2n_ecc_preferences *cbmc_allocate_s2n_ecc_preferences()
{
    struct s2n_ecc_preferences *s2n_ecc_preferences = malloc(sizeof(*s2n_ecc_preferences));
    return s2n_ecc_preferences;
}

struct s2n_security_policy *cbmc_allocate_s2n_security_policy()
{
    struct s2n_security_policy *s2n_security_policy = malloc(sizeof(*s2n_security_policy));
    PTR_ENSURE_REF(s2n_security_policy);
    s2n_security_policy->cipher_preferences                = cbmc_allocate_s2n_cipher_preferences();
    s2n_security_policy->kem_preferences                   = cbmc_allocate_s2n_kem_preferences();
    s2n_security_policy->signature_preferences             = cbmc_allocate_s2n_signature_preferences();
    s2n_security_policy->certificate_signature_preferences = cbmc_allocate_s2n_signature_preferences();
    s2n_security_policy->ecc_preferences                   = cbmc_allocate_s2n_ecc_preferences();
    return s2n_security_policy;
}

X509_STORE *cbmc_allocate_X509_STORE()
{
    X509_STORE *x509_store = malloc(sizeof(*x509_store));
    return x509_store;
}

void cbmc_populate_s2n_x509_trust_store(struct s2n_x509_trust_store *s2n_x509_trust_store)
{
    CBMC_ENSURE_REF(s2n_x509_trust_store);
    s2n_x509_trust_store->trust_store = cbmc_allocate_X509_STORE();
}

struct s2n_config *cbmc_allocate_s2n_config()
{
    struct s2n_config *s2n_config = malloc(sizeof(*s2n_config));
    PTR_ENSURE_REF(s2n_config);
    s2n_config->dhparams                = cbmc_allocate_dh_params();
    s2n_config->domain_name_to_cert_map = cbmc_allocate_s2n_map();
    /* `s2n_config->default_certs_by_type` is never allocated.
     * If required, this initialization should be done in the proof harness.
     */
    cbmc_populate_s2n_blob(&s2n_config->application_protocols);
    s2n_config->security_policy      = cbmc_allocate_s2n_security_policy();
    s2n_config->sys_clock_ctx        = malloc(sizeof(*(s2n_config->sys_clock_ctx)));
    s2n_config->monotonic_clock_ctx  = malloc(sizeof(*(s2n_config->monotonic_clock_ctx)));
    s2n_config->client_hello_cb      = malloc(sizeof(*(s2n_config->client_hello_cb))); /* Function pointer. */
    s2n_config->client_hello_cb_ctx  = malloc(sizeof(*(s2n_config->client_hello_cb_ctx)));
    s2n_config->ticket_keys          = cbmc_allocate_s2n_set();
    s2n_config->ticket_key_hashes    = cbmc_allocate_s2n_set();
    s2n_config->cache_store_data     = malloc(sizeof(*(s2n_config->cache_store_data)));
    s2n_config->cache_retrieve_data  = malloc(sizeof(*(s2n_config->cache_retrieve_data)));
    s2n_config->cache_delete_data    = malloc(sizeof(*(s2n_config->cache_delete_data)));
    s2n_config->data_for_verify_host = malloc(sizeof(*(s2n_config->data_for_verify_host)));
    cbmc_populate_s2n_x509_trust_store(&s2n_config->trust_store);
    s2n_config->psk_selection_ctx  = malloc(sizeof(*(s2n_config->psk_selection_ctx)));
    s2n_config->key_log_ctx        = malloc(sizeof(*(s2n_config->key_log_ctx)));
    s2n_config->session_ticket_ctx = malloc(sizeof(*(s2n_config->session_ticket_ctx)));
    return s2n_config;
}

void cbmc_populate_s2n_rsa_key(struct s2n_rsa_key *s2n_rsa_key)
{
    CBMC_ENSURE_REF(s2n_rsa_key);
    s2n_rsa_key->rsa = malloc(sizeof(*(s2n_rsa_key->rsa)));
}

void cbmc_populate_s2n_ecdsa_key(struct s2n_ecdsa_key *s2n_ecdsa_key)
{
    CBMC_ENSURE_REF(s2n_ecdsa_key);
    s2n_ecdsa_key->ec_key = malloc(sizeof(*(s2n_ecdsa_key->ec_key)));
}

void cbmc_populate_s2n_pkey(struct s2n_pkey *s2n_pkey)
{
    CBMC_ENSURE_REF(s2n_pkey);
    cbmc_populate_s2n_rsa_key(&(s2n_pkey->key.rsa_key));
    cbmc_populate_s2n_ecdsa_key(&(s2n_pkey->key.ecdsa_key));
    /* `s2n_pkey->pkey`
     * `s2n_pkey->size`
     * `s2n_pkey->sign`
     * `s2n_pkey->verify`
     * `s2n_pkey->encrypt`
     * `s2n_pkey->decrypt`
     * `s2n_pkey->match`
     * `s2n_pkey->free`
     * `s2n_pkey->check_key` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
}

struct s2n_pkey *cbmc_allocate_s2n_pkey()
{
    struct s2n_pkey *s2n_pkey = malloc(sizeof(*s2n_pkey));
    cbmc_populate_s2n_pkey(s2n_pkey);
    return s2n_pkey;
}

void cbmc_populate_s2n_ecc_evp_params(struct s2n_ecc_evp_params *s2n_ecc_evp_params)
{
    CBMC_ENSURE_REF(s2n_ecc_evp_params);
    /* `s2n_ecc_evp_params->negotiated_curve` is never allocated.
     * If required, this initialization should be done in the proof harness.
     */
    s2n_ecc_evp_params->evp_pkey = malloc(sizeof(*(s2n_ecc_evp_params->evp_pkey)));
}

struct s2n_ecc_named_curve *cbmc_allocate_s2n_ecc_named_curve()
{
    struct s2n_ecc_named_curve *s2n_ecc_named_curve = malloc(sizeof(*s2n_ecc_named_curve));
    /* `s2n_ecc_named_curve->name`
     * `s2n_ecc_named_curve->generate_key` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
    return s2n_ecc_named_curve;
}

struct s2n_kem *cbmc_allocate_s2n_kem()
{
    struct s2n_kem *s2n_kem = malloc(sizeof(*s2n_kem));
    /* `s2n_kem->name`
     * `s2n_kem->generate_keypair`
     * `s2n_kem->encapsulate`
     * `s2n_kem->decapsulate` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
}

struct s2n_kem_group *cbmc_allocate_s2n_kem_group()
{
    struct s2n_kem_group *s2n_kem_group = malloc(sizeof(*s2n_kem_group));
    PTR_ENSURE_REF(s2n_kem_group);
    /* `s2n_kem_group->name` is never allocated.
     * If required, this initialization should be done in the proof harness.
     */
    s2n_kem_group->curve = cbmc_allocate_s2n_ecc_named_curve();
    s2n_kem_group->kem   = cbmc_allocate_s2n_kem();
    return s2n_kem_group;
}

void cbmc_populate_s2n_kem_params(struct s2n_kem_params *s2n_kem_params)
{
    CBMC_ENSURE_REF(s2n_kem_params);
    s2n_kem_params->kem = cbmc_allocate_s2n_kem();
    cbmc_populate_s2n_blob(&(s2n_kem_params->public_key));
    cbmc_populate_s2n_blob(&(s2n_kem_params->private_key));
    cbmc_populate_s2n_blob(&(s2n_kem_params->shared_secret));
}

void cbmc_populate_s2n_kem_group_params(struct s2n_kem_group_params *s2n_kem_group_params)
{
    CBMC_ENSURE_REF(s2n_kem_group_params);
    s2n_kem_group_params->kem_group = cbmc_allocate_s2n_kem_group();
    cbmc_populate_s2n_kem_params(&(s2n_kem_group_params->kem_params));
    cbmc_populate_s2n_ecc_evp_params(&(s2n_kem_group_params->ecc_params));
}

struct s2n_kem_group_params *cbmc_allocate_s2n_kem_group_params()
{
    struct s2n_kem_group_params *s2n_kem_group_params = malloc(sizeof(*s2n_kem_group_params));
    cbmc_populate_s2n_kem_group_params(s2n_kem_group_params);
    return s2n_kem_group_params;
}

void cbmc_populate_s2n_signature_scheme(struct s2n_signature_scheme *s2n_signature_scheme)
{
    CBMC_ENSURE_REF(s2n_signature_scheme);
    s2n_signature_scheme->signature_curve = cbmc_allocate_s2n_ecc_named_curve();
}

struct s2n_kex *cbmc_allocate_s2n_kex()
{
    struct s2n_kex *s2n_kex = malloc(sizeof(*s2n_kex));
    /* `s2n_kex->hybrid`
     * `s2n_kex->connection_supported`
     * `s2n_kex->configure_connection`
     * `s2n_kex->server_key_recv_read_data`
     * `s2n_kex->server_key_recv_parse_data`
     * `s2n_kex->server_key_send`
     * `s2n_kex->client_key_recv`
     * `s2n_kex->client_key_send`
     * `s2n_kex->prf` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
    return s2n_kex;
}

struct s2n_cipher *cbmc_allocate_s2n_cipher()
{
    struct s2n_cipher *s2n_cipher = malloc(sizeof(*s2n_cipher));
    /* `s2n_cipher->io.stream`
     * `s2n_cipher->io.aead`
     * `s2n_cipher->io.cbc`
     * `s2n_cipher->io.comp`
     * `s2n_cipher->is_available`
     * `s2n_cipher->init`
     * `s2n_cipher->set_decryption_key`
     * `s2n_cipher->set_encryption_key`
     * `s2n_cipher->destroy_key` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
    return s2n_cipher;
}

struct s2n_record_algorithm *cbmc_allocate_s2n_record_algorithm()
{
    struct s2n_record_algorithm *s2n_record_algorithm = malloc(sizeof(*s2n_record_algorithm));
    PTR_ENSURE_REF(s2n_record_algorithm);
    s2n_record_algorithm->cipher = cbmc_allocate_s2n_cipher();
    return s2n_record_algorithm;
}

struct s2n_cipher_suite *cbmc_allocate_s2n_cipher_suite()
{
    struct s2n_cipher_suite *s2n_cipher_suite = malloc(sizeof(*s2n_cipher_suite));
    PTR_ENSURE_REF(s2n_cipher_suite);
    /* `s2n_cipher_suite->name`
     * `s2n_cipher_suite->all_record_algs`
     * `s2n_cipher_suite->sslv3_cipher_suite` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
    s2n_cipher_suite->key_exchange_alg = cbmc_allocate_s2n_kex();
    s2n_cipher_suite->record_alg       = cbmc_allocate_s2n_record_algorithm();
    s2n_cipher_suite->sslv3_record_alg = cbmc_allocate_s2n_record_algorithm();
    return s2n_cipher_suite;
}

void cbmc_populate_s2n_session_key(struct s2n_session_key *s2n_session_key)
{
    CBMC_ENSURE_REF(s2n_session_key);
    s2n_session_key->evp_cipher_ctx = malloc(sizeof(*(s2n_session_key->evp_cipher_ctx)));
}

void cbmc_populate_s2n_kex_parameters(struct s2n_kex_parameters *s2n_kex_parameters)
{
	cbmc_populate_s2n_dh_params(&(s2n_kex_parameters->server_dh_params));
	cbmc_populate_s2n_ecc_evp_params(&(s2n_kex_parameters->server_ecc_evp_params));
	/* `s2n_crypto_parameters->mutually_supported_curves`
	 * `s2n_crypto_parameters->client_ecc_evp_params`
	 * `s2n_crypto_parameters->client_kem_group_params`
	 * `s2n_crypto_parameters->mutually_supported_kem_groups` are never allocated.
	 * If required, these initializations should be done in the proof harness.
	 */
	cbmc_populate_s2n_kem_group_params(&(s2n_kex_parameters->server_kem_group_params));
	cbmc_populate_s2n_kem_params(&(s2n_kex_parameters->kem_params));
	cbmc_populate_s2n_blob(&(s2n_kex_parameters->client_key_exchange_message));
	cbmc_populate_s2n_blob(&(s2n_kex_parameters->client_pq_kem_extension));
}

void cbmc_populate_s2n_crypto_parameters(struct s2n_crypto_parameters *s2n_crypto_parameters)
{
    CBMC_ENSURE_REF(s2n_crypto_parameters);
    s2n_crypto_parameters->cipher_suite = cbmc_allocate_s2n_cipher_suite();
    cbmc_populate_s2n_session_key(&(s2n_crypto_parameters->client_key));
    cbmc_populate_s2n_session_key(&(s2n_crypto_parameters->server_key));
    cbmc_populate_s2n_hmac_state(&(s2n_crypto_parameters->client_record_mac));
    cbmc_populate_s2n_hmac_state(&(s2n_crypto_parameters->server_record_mac));
}

struct s2n_crypto_parameters *cbmc_allocate_s2n_crypto_parameters()
{
    struct s2n_crypto_parameters *s2n_crypto_parameters = malloc(sizeof(*s2n_crypto_parameters));
    cbmc_populate_s2n_crypto_parameters(s2n_crypto_parameters);
    return s2n_crypto_parameters;
}

void cbmc_populate_s2n_cert(struct s2n_cert *s2n_cert)
{
    CBMC_ENSURE_REF(s2n_cert);
    cbmc_populate_s2n_blob(&(s2n_cert->raw));
    /* `s2n_cert->next` is never allocated.
     * If required, this initialization should be done in the proof harness.
     */
}

struct s2n_cert *cbmc_allocate_s2n_cert()
{
    struct s2n_cert *s2n_cert = malloc(sizeof(*s2n_cert));
    cbmc_populate_s2n_cert(s2n_cert);
    return s2n_cert;
}

void cbmc_populate_s2n_cert_chain(struct s2n_cert_chain *s2n_cert_chain)
{
    CBMC_ENSURE_REF(s2n_cert_chain);
    s2n_cert_chain->head = cbmc_allocate_s2n_cert();
}

struct s2n_cert_chain *cbmc_allocate_s2n_cert_chain()
{
    struct s2n_cert_chain *s2n_cert_chain = malloc(sizeof(*s2n_cert_chain));
    cbmc_populate_s2n_cert_chain(s2n_cert_chain);
    return s2n_cert_chain;
}

void cbmc_populate_s2n_cert_chain_and_key(struct s2n_cert_chain_and_key *s2n_cert_chain_and_key)
{
    CBMC_ENSURE_REF(s2n_cert_chain_and_key);
    s2n_cert_chain_and_key->cert_chain  = cbmc_allocate_s2n_cert_chain();
    s2n_cert_chain_and_key->private_key = cbmc_allocate_s2n_pkey();
    cbmc_populate_s2n_blob(&(s2n_cert_chain_and_key->ocsp_status));
    cbmc_populate_s2n_blob(&(s2n_cert_chain_and_key->sct_list));
    s2n_cert_chain_and_key->san_names = cbmc_allocate_s2n_array();
    s2n_cert_chain_and_key->cn_names  = cbmc_allocate_s2n_array();
    s2n_cert_chain_and_key->context   = malloc(sizeof(*(s2n_cert_chain_and_key->context)));
}

void cbmc_populate_s2n_handshake_parameters(struct s2n_handshake_parameters *s2n_handshake_parameters)
{
    CBMC_ENSURE_REF(s2n_handshake_parameters);
    cbmc_populate_s2n_pkey(&(s2n_handshake_parameters->server_public_key));
    cbmc_populate_s2n_pkey(&(s2n_handshake_parameters->client_public_key));
    cbmc_populate_s2n_signature_scheme(&(s2n_handshake_parameters->server_cert_sig_scheme));
    cbmc_populate_s2n_blob(&(s2n_handshake_parameters->client_cert_chain));
    cbmc_populate_s2n_signature_scheme(&(s2n_handshake_parameters->client_cert_sig_scheme));
    cbmc_populate_s2n_cert_chain_and_key(s2n_handshake_parameters->our_chain_and_key);
    /* `s2n_handshake_parameters->exact_sni_matches`
     * `s2n_handshake_parameters->wc_sni_matches` are never allocated.
     * If required, these initializations should be done in the proof harness.
     */
}

void cbmc_populate_s2n_early_data_config(struct s2n_early_data_config *s2n_early_data_config)
{
    CBMC_ENSURE_REF(s2n_early_data_config);
    s2n_early_data_config->cipher_suite = cbmc_allocate_s2n_cipher_suite();
    cbmc_populate_s2n_blob(&(s2n_early_data_config->application_protocol));
    cbmc_populate_s2n_blob(&(s2n_early_data_config->context));
}

void cbmc_populate_s2n_psk(struct s2n_psk *s2n_psk)
{
    CBMC_ENSURE_REF(s2n_psk);
    cbmc_populate_s2n_blob(&(s2n_psk->identity));
    cbmc_populate_s2n_blob(&(s2n_psk->secret));
    cbmc_populate_s2n_blob(&(s2n_psk->early_secret));
    cbmc_populate_s2n_early_data_config(&(s2n_psk->early_data_config));
}

struct s2n_psk *cbmc_allocate_s2n_psk()
{
    struct s2n_psk *s2n_psk = malloc(sizeof(*s2n_psk));
    cbmc_populate_s2n_psk(s2n_psk);
    return s2n_psk;
}

void cbmc_populate_s2n_psk_parameters(struct s2n_psk_parameters *s2n_psk_parameters)
{
    CBMC_ENSURE_REF(s2n_psk_parameters);
    cbmc_populate_s2n_blob(&(s2n_psk_parameters->psk_list.mem));
    s2n_psk_parameters->chosen_psk = cbmc_allocate_s2n_psk();
}

void cbmc_populate_s2n_prf_working_space(struct s2n_prf_working_space *s2n_prf_working_space)
{
    CBMC_ENSURE_REF(s2n_prf_working_space);
    /* `s2n_prf_working_space->tls.p_hash_hmac_impl` is never allocated.
     * It is always initialized based on the hashing algorithm.
     * If required, this initialization should be done in the validation function.
     */
    cbmc_populate_s2n_hmac_state(&(s2n_prf_working_space->p_hash.s2n_hmac));
    cbmc_populate_s2n_evp_hmac_state(&(s2n_prf_working_space->p_hash.evp_hmac));
}

struct s2n_prf_working_space* cbmc_allocate_s2n_prf_working_space()
{
    struct s2n_prf_working_space *workspace = malloc(sizeof(*workspace));
    cbmc_populate_s2n_prf_working_space(workspace);
    return workspace;
}

void cbmc_populate_s2n_handshake(struct s2n_handshake *s2n_handshake)
{
    CBMC_ENSURE_REF(s2n_handshake);
    cbmc_populate_s2n_stuffer(&(s2n_handshake->io));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->md5));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->sha1));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->sha224));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->sha256));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->sha384));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->sha512));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->md5_sha1));
    cbmc_populate_s2n_hash_state(&(s2n_handshake->hashes->hash_workspace));
    /* `s2n_handshake->early_data_async_state.conn` is never allocated.
     * If required, this initialization should be done in the validation function.
     */
}

void cbmc_populate_s2n_client_hello(struct s2n_client_hello *s2n_client_hello)
{
    CBMC_ENSURE_REF(s2n_client_hello);
    cbmc_populate_s2n_blob(&(s2n_client_hello->raw_message));
    cbmc_populate_s2n_blob(&(s2n_client_hello->cipher_suites));
}

void cbmc_populate_s2n_x509_validator(struct s2n_x509_validator *s2n_x509_validator)
{
    CBMC_ENSURE_REF(s2n_x509_validator);
    s2n_x509_validator->trust_store = malloc(sizeof(*(s2n_x509_validator->trust_store)));
    if (s2n_x509_validator->trust_store != NULL) {
        s2n_x509_validator->trust_store->trust_store = malloc(sizeof(*(s2n_x509_validator->trust_store->trust_store)));
    }
    s2n_x509_validator->store_ctx            = malloc(sizeof(*(s2n_x509_validator->store_ctx)));
    s2n_x509_validator->cert_chain_from_wire = malloc(sizeof(*(s2n_x509_validator->cert_chain_from_wire)));
}

void cbmc_populate_s2n_ticket_fields(struct s2n_ticket_fields *s2n_ticket_fields)
{
    CBMC_ENSURE_REF(s2n_ticket_fields);
    cbmc_populate_s2n_blob(&(s2n_ticket_fields->session_secret));
}

void cbmc_populate_s2n_connection(struct s2n_connection *s2n_connection)
{
    CBMC_ENSURE_REF(s2n_connection);
    s2n_connection->config                   = cbmc_allocate_s2n_config();
    s2n_connection->security_policy_override = cbmc_allocate_s2n_security_policy();
    s2n_connection->context                  = malloc(sizeof(*(s2n_connection->context)));
    s2n_connection->secret_cb                = malloc(sizeof(*(s2n_connection->secret_cb))); /* Function pointer. */
    s2n_connection->secret_cb_context        = malloc(sizeof(*(s2n_connection->secret_cb_context)));
    s2n_connection->send                     = malloc(sizeof(*(s2n_connection->send))); /* Function pointer. */
    s2n_connection->recv                     = malloc(sizeof(*(s2n_connection->recv))); /* Function pointer. */
    s2n_connection->send_io_context          = malloc(sizeof(*(s2n_connection->secret_cb)));
    s2n_connection->recv_io_context          = malloc(sizeof(*(s2n_connection->secret_cb)));
    cbmc_populate_s2n_crypto_parameters(s2n_connection->initial);
    cbmc_populate_s2n_crypto_parameters(s2n_connection->secure);
    cbmc_populate_s2n_kex_parameters(&(s2n_connection->kex_params));
    s2n_connection->client = cbmc_allocate_s2n_crypto_parameters();
    s2n_connection->server = cbmc_allocate_s2n_crypto_parameters();
    cbmc_populate_s2n_handshake_parameters(&(s2n_connection->handshake_params));
    cbmc_populate_s2n_psk_parameters(&(s2n_connection->psk_params));
    s2n_connection->prf_space = cbmc_allocate_s2n_prf_working_space();
    cbmc_populate_s2n_stuffer(&(s2n_connection->header_in));
    cbmc_populate_s2n_stuffer(&(s2n_connection->in));
    cbmc_populate_s2n_stuffer(&(s2n_connection->out));
    cbmc_populate_s2n_stuffer(&(s2n_connection->alert_in));
    cbmc_populate_s2n_handshake(&(s2n_connection->handshake));
    cbmc_populate_s2n_blob(&(s2n_connection->status_response));
    cbmc_populate_s2n_blob(&(s2n_connection->ct_response));
    cbmc_populate_s2n_blob(&(s2n_connection->our_quic_transport_parameters));
    cbmc_populate_s2n_blob(&(s2n_connection->peer_quic_transport_parameters));
    cbmc_populate_s2n_client_hello(&(s2n_connection->client_hello));
    cbmc_populate_s2n_x509_validator(&(s2n_connection->x509_validator));
    s2n_connection->verify_host_fn       = malloc(sizeof(*(s2n_connection->verify_host_fn))); /* Function pointer. */
    s2n_connection->data_for_verify_host = malloc(sizeof(*(s2n_connection->data_for_verify_host)));
    cbmc_populate_s2n_blob(&(s2n_connection->client_ticket));
    cbmc_populate_s2n_ticket_fields(&(s2n_connection->tls13_ticket_fields));
    cbmc_populate_s2n_stuffer(&(s2n_connection->client_ticket_to_decrypt));
    cbmc_populate_s2n_blob(&(s2n_connection->application_protocols_overridden));
    cbmc_populate_s2n_blob(&(s2n_connection->cookie));
    cbmc_populate_s2n_blob(&(s2n_connection->server_early_data_context));
}

struct s2n_connection *cbmc_allocate_s2n_connection()
{
    struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));
    cbmc_populate_s2n_connection(s2n_connection);
    return s2n_connection;
}

struct s2n_socket_read_io_context *cbmc_allocate_s2n_socket_read_io_context()
{
    struct s2n_socket_read_io_context *s2n_socket_read_io_context = malloc(sizeof(*s2n_socket_read_io_context));
    return s2n_socket_read_io_context;
}

struct s2n_socket_write_io_context *cbmc_allocate_s2n_socket_write_io_context()
{
    struct s2n_socket_write_io_context *s2n_socket_write_io_context = malloc(sizeof(*s2n_socket_write_io_context));
    return s2n_socket_write_io_context;
}
