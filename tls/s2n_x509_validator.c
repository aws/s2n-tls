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

#include "crypto/s2n_openssl.h"
#include "crypto/s2n_openssl_x509.h"
#include "utils/s2n_asn1_time.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_rfc5952.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

#if S2N_OCSP_STAPLING_SUPPORTED
#include <openssl/ocsp.h>
DEFINE_POINTER_CLEANUP_FUNC(OCSP_RESPONSE*, OCSP_RESPONSE_free);
DEFINE_POINTER_CLEANUP_FUNC(OCSP_BASICRESP*, OCSP_BASICRESP_free);
#endif

#ifndef X509_V_FLAG_PARTIAL_CHAIN
#define X509_V_FLAG_PARTIAL_CHAIN 0x80000
#endif

#define DEFAULT_MAX_CHAIN_DEPTH 7
/* Time used by default for nextUpdate if none provided in OCSP: 1 hour since thisUpdate. */
#define DEFAULT_OCSP_NEXT_UPDATE_PERIOD 3600000000000

uint8_t s2n_x509_ocsp_stapling_supported(void) {
    return S2N_OCSP_STAPLING_SUPPORTED;
}

void s2n_x509_trust_store_init_empty(struct s2n_x509_trust_store *store) {
    store->trust_store = NULL;
}

uint8_t s2n_x509_trust_store_has_certs(struct s2n_x509_trust_store *store) {
    return store->trust_store ? (uint8_t) 1 : (uint8_t) 0;
}

int s2n_x509_trust_store_from_system_defaults(struct s2n_x509_trust_store *store) {
    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
        POSIX_ENSURE_REF(store->trust_store);
    }

    int err_code = X509_STORE_set_default_paths(store->trust_store);
    if (!err_code) {
        s2n_x509_trust_store_wipe(store);
        POSIX_BAIL(S2N_ERR_X509_TRUST_STORE);
    }

    X509_STORE_set_flags(store->trust_store, X509_VP_FLAG_DEFAULT);

    return 0;
}

int s2n_x509_trust_store_add_pem(struct s2n_x509_trust_store *store, const char *pem)
{
    POSIX_ENSURE_REF(store);
    POSIX_ENSURE_REF(pem);

    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
    }

    DEFER_CLEANUP(struct s2n_stuffer pem_in_stuffer = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer der_out_stuffer = {0}, s2n_stuffer_free);

    POSIX_GUARD(s2n_stuffer_alloc_ro_from_string(&pem_in_stuffer, pem));
    POSIX_GUARD(s2n_stuffer_growable_alloc(&der_out_stuffer, 2048));

    do {
        DEFER_CLEANUP(struct s2n_blob next_cert = {0}, s2n_free);

        POSIX_GUARD(s2n_stuffer_certificate_from_pem(&pem_in_stuffer, &der_out_stuffer));
        POSIX_GUARD(s2n_alloc(&next_cert, s2n_stuffer_data_available(&der_out_stuffer)));
        POSIX_GUARD(s2n_stuffer_read(&der_out_stuffer, &next_cert));

        const uint8_t *data = next_cert.data;
        DEFER_CLEANUP(X509 *ca_cert = d2i_X509(NULL, &data, next_cert.size), X509_free_pointer);
        S2N_ERROR_IF(ca_cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

        if (!X509_STORE_add_cert(store->trust_store, ca_cert)) {
            unsigned long error = ERR_get_error();
            POSIX_ENSURE(ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE, S2N_ERR_DECODE_CERTIFICATE);
        }
    } while (s2n_stuffer_data_available(&pem_in_stuffer));

    return 0;
}

int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_pem_filename, const char *ca_dir) {
    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
        POSIX_ENSURE_REF(store->trust_store);
    }

    int err_code = X509_STORE_load_locations(store->trust_store, ca_pem_filename, ca_dir);
    if (!err_code) {
        s2n_x509_trust_store_wipe(store);
        POSIX_BAIL(S2N_ERR_X509_TRUST_STORE);
    }

    /* It's a likely scenario if this function is called, a self-signed certificate is used, and that is was generated
     * without a trust anchor. However if you call this function, the assumption is you trust ca_file or path and if a certificate
     * is encountered that's in that path, it should be trusted. The following flag tells libcrypto to not care that the cert
     * is missing a root anchor. */
    unsigned long flags = X509_VP_FLAG_DEFAULT;
    flags |=  X509_V_FLAG_PARTIAL_CHAIN;
    X509_STORE_set_flags(store->trust_store, flags);

    return 0;
}

void s2n_x509_trust_store_wipe(struct s2n_x509_trust_store *store) {
    if (store->trust_store) {
        X509_STORE_free(store->trust_store);
        store->trust_store = NULL;
    }
}

int s2n_x509_validator_init_no_x509_validation(struct s2n_x509_validator *validator) {
    POSIX_ENSURE_REF(validator);
    validator->trust_store = NULL;
    validator->store_ctx = NULL;
    validator->skip_cert_validation = 1;
    validator->check_stapled_ocsp = 0;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;
    validator->state = INIT;
    validator->cert_chain_from_wire = sk_X509_new_null();

    return 0;
}

int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, uint8_t check_ocsp) {
    POSIX_ENSURE_REF(trust_store);
    validator->trust_store = trust_store;
    validator->skip_cert_validation = 0;
    validator->check_stapled_ocsp = check_ocsp;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;
    validator->store_ctx = NULL;
    if (validator->trust_store->trust_store) {
        validator->store_ctx = X509_STORE_CTX_new();
        POSIX_ENSURE_REF(validator->store_ctx);
    }
    validator->cert_chain_from_wire = sk_X509_new_null();
    validator->state = INIT;

    return 0;
}

static inline void wipe_cert_chain(STACK_OF(X509) *cert_chain) {
    if (cert_chain) {
        sk_X509_pop_free(cert_chain, X509_free);
    }
}

void s2n_x509_validator_wipe(struct s2n_x509_validator *validator) {
    if (validator->store_ctx) {
        X509_STORE_CTX_free(validator->store_ctx);
        validator->store_ctx = NULL;
    }
    wipe_cert_chain(validator->cert_chain_from_wire);
    validator->cert_chain_from_wire = NULL;
    validator->trust_store = NULL;
    validator->skip_cert_validation = 0;
    validator->state = UNINIT;
    validator->max_chain_depth = 0;
}

int s2n_x509_validator_set_max_chain_depth(struct s2n_x509_validator *validator, uint16_t max_depth) {
    POSIX_ENSURE_REF(validator);
    S2N_ERROR_IF(max_depth == 0, S2N_ERR_INVALID_ARGUMENT);

    validator->max_chain_depth = max_depth;
    return 0;
}

/*
 * For each name in the cert. Iterate them. Call the callback. If one returns true, then consider it validated,
 * if none of them return true, the cert is considered invalid.
 */
static uint8_t s2n_verify_host_information(struct s2n_x509_validator *validator, struct s2n_connection *conn, X509 *public_cert) {
    (void)validator;
    uint8_t verified = 0;
    uint8_t san_found = 0;

    /* Check SubjectAltNames before CommonName as per RFC 6125 6.4.4 */
    STACK_OF(GENERAL_NAME) *names_list = X509_get_ext_d2i(public_cert, NID_subject_alt_name, NULL, NULL);
    int n = sk_GENERAL_NAME_num(names_list);
    for (int i = 0; i < n && !verified; i++) {
        GENERAL_NAME *current_name = sk_GENERAL_NAME_value(names_list, i);
        if (current_name->type == GEN_DNS) {
            san_found = 1;

            const char *name = (const char *) ASN1_STRING_data(current_name->d.ia5);
            size_t name_len = (size_t) ASN1_STRING_length(current_name->d.ia5);

            verified = conn->verify_host_fn(name, name_len, conn->data_for_verify_host);
        } else if (current_name->type == GEN_URI) {
            const char *name = (const char *) ASN1_STRING_data(current_name->d.ia5);
            size_t name_len = (size_t) ASN1_STRING_length(current_name->d.ia5);

            verified = conn->verify_host_fn(name, name_len, conn->data_for_verify_host);
        } else if (current_name->type == GEN_IPADD) {
            san_found = 1;
            /* try to validate an IP address if it's in the subject alt name. */
            const unsigned char *ip_addr = current_name->d.iPAddress->data;
            size_t ip_addr_len = (size_t)current_name->d.iPAddress->length;

            s2n_result parse_result = S2N_RESULT_ERROR;
            s2n_stack_blob(address, INET6_ADDRSTRLEN + 1, INET6_ADDRSTRLEN + 1);
            if (ip_addr_len == 4) {
                parse_result = s2n_inet_ntop(AF_INET, ip_addr, &address);
            } else if (ip_addr_len == 16) {
                parse_result = s2n_inet_ntop(AF_INET6, ip_addr, &address);
            }

            /* strlen should be safe here since we made sure we were null terminated AND that inet_ntop succeeded */
            if (s2n_result_is_ok(parse_result)) {
                verified = conn->verify_host_fn(
                               (const char *)address.data,
                               strlen((const char *)address.data),
                               conn->data_for_verify_host);
            }
        }
    }

    GENERAL_NAMES_free(names_list);

    /* if no SubjectAltNames of type DNS found, go to the common name. */
    if (!verified && !san_found) {
        X509_NAME *subject_name = X509_get_subject_name(public_cert);
        if (subject_name) {
            int next_idx = 0, curr_idx = -1;
            while ((next_idx = X509_NAME_get_index_by_NID(subject_name, NID_commonName, curr_idx)) >= 0) {
                curr_idx = next_idx;
            }

            if (curr_idx >= 0) {
                ASN1_STRING *common_name =
                        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject_name, curr_idx));

                if (common_name) {
                    char peer_cn[255];
                    static size_t peer_cn_size = sizeof(peer_cn);
                    POSIX_CHECKED_MEMSET(&peer_cn, 0, peer_cn_size);

                    /* X520CommonName allows the following ANSI string types per RFC 5280 Appendix A.1 */
                    if (ASN1_STRING_type(common_name) == V_ASN1_TELETEXSTRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_PRINTABLESTRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_UNIVERSALSTRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_UTF8STRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_BMPSTRING ) {

                        size_t len = (size_t) ASN1_STRING_length(common_name);

                        POSIX_ENSURE_LTE(len, sizeof(peer_cn) - 1);
                        POSIX_CHECKED_MEMCPY(peer_cn, ASN1_STRING_data(common_name), len);
                        verified = conn->verify_host_fn(peer_cn, len, conn->data_for_verify_host);
                    }
                }
            }
        }
    }

    return verified;
}

static S2N_RESULT s2n_x509_validator_read_asn1_cert(struct s2n_stuffer *cert_chain_in_stuffer, struct s2n_blob *asn1_cert) {
    uint32_t certificate_size = 0;

    RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(cert_chain_in_stuffer, &certificate_size));
    RESULT_ENSURE(certificate_size > 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(certificate_size <= s2n_stuffer_data_available(cert_chain_in_stuffer), S2N_ERR_CERT_INVALID);

    asn1_cert->size = certificate_size;
    asn1_cert->data = s2n_stuffer_raw_read(cert_chain_in_stuffer, certificate_size);
    RESULT_ENSURE_REF(asn1_cert->data);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_read_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len) {
    RESULT_ENSURE(validator->skip_cert_validation || s2n_x509_trust_store_has_certs(validator->trust_store), S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    struct s2n_blob cert_chain_blob = {.data = cert_chain_in, .size = cert_chain_len};
    DEFER_CLEANUP(struct s2n_stuffer cert_chain_in_stuffer = { 0 }, s2n_stuffer_free);

    RESULT_GUARD_POSIX(s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob));

    X509 *server_cert = NULL;

    while (s2n_stuffer_data_available(&cert_chain_in_stuffer) && sk_X509_num(validator->cert_chain_from_wire) < validator->max_chain_depth) {
        struct s2n_blob asn1_cert = { 0 };
        RESULT_GUARD(s2n_x509_validator_read_asn1_cert(&cert_chain_in_stuffer, &asn1_cert));

        const uint8_t *data = asn1_cert.data;

        /* the cert is der encoded, just convert it. */
        server_cert = d2i_X509(NULL, &data, asn1_cert.size);
        RESULT_ENSURE_REF(server_cert);

        /* add the cert to the chain. */
        if (!sk_X509_push(validator->cert_chain_from_wire, server_cert)) {
            /* After the cert is added to cert_chain_from_wire, it will be freed with the call to
             * s2n_x509_validator_wipe. If adding the cert fails, free it now instead. */
            X509_free(server_cert);
            RESULT_BAIL(S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
        }

        if (!validator->skip_cert_validation) {
            RESULT_ENSURE_OK(s2n_validate_certificate_signature(conn, server_cert), S2N_ERR_CERT_UNTRUSTED);
        }

        /* certificate extensions is a field in TLS 1.3 - https://tools.ietf.org/html/rfc8446#section-4.4.2 */
        if (conn->actual_protocol_version >= S2N_TLS13) {
            s2n_parsed_extensions_list parsed_extensions_list = { 0 };
            RESULT_GUARD_POSIX(s2n_extension_list_parse(&cert_chain_in_stuffer, &parsed_extensions_list));
        }
    }

    /* if this occurred we exceeded validator->max_chain_depth */
    RESULT_ENSURE(validator->skip_cert_validation || s2n_stuffer_data_available(&cert_chain_in_stuffer) == 0,
            S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
    RESULT_ENSURE(sk_X509_num(validator->cert_chain_from_wire) > 0, S2N_ERR_NO_CERT_FOUND);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_process_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len) {
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    RESULT_GUARD(s2n_x509_validator_read_cert_chain(validator, conn, cert_chain_in, cert_chain_len));

    if (validator->skip_cert_validation) {
        return S2N_RESULT_OK;
    }

    X509 *leaf = sk_X509_value(validator->cert_chain_from_wire, 0);
    RESULT_ENSURE_REF(leaf);

    if (conn->verify_host_fn) {
        RESULT_ENSURE(s2n_verify_host_information(validator, conn, leaf), S2N_ERR_CERT_UNTRUSTED);
    }

    RESULT_GUARD_OSSL(X509_STORE_CTX_init(validator->store_ctx, validator->trust_store->trust_store, leaf,
            validator->cert_chain_from_wire), S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    validator->state = READY_TO_VERIFY;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_verify_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn) {
    RESULT_ENSURE(validator->state == READY_TO_VERIFY, S2N_ERR_INVALID_CERT_STATE);

    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(validator->store_ctx);
    X509_VERIFY_PARAM_set_depth(param, validator->max_chain_depth);

    uint64_t current_sys_time = 0;
    conn->config->wall_clock(conn->config->sys_clock_ctx, &current_sys_time);

    /* this wants seconds not nanoseconds */
    time_t current_time = (time_t)(current_sys_time / 1000000000);
    X509_STORE_CTX_set_time(validator->store_ctx, 0, current_time);

    int verify_ret = X509_verify_cert(validator->store_ctx);
    if (verify_ret <= 0) {
        int ossl_error = X509_STORE_CTX_get_error(validator->store_ctx);
        switch (ossl_error) {
            case X509_V_ERR_CERT_HAS_EXPIRED:
                RESULT_BAIL(S2N_ERR_CERT_EXPIRED);
            default:
                RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
    }

    validator->state = VALIDATED;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_read_leaf_info(struct s2n_connection *conn, uint8_t *cert_chain_in, uint32_t cert_chain_len,
        struct s2n_pkey *public_key, s2n_pkey_type *pkey_type, s2n_parsed_extensions_list *first_certificate_extensions) {
    struct s2n_blob cert_chain_blob = {.data = cert_chain_in, .size = cert_chain_len};
    DEFER_CLEANUP(struct s2n_stuffer cert_chain_in_stuffer = { 0 }, s2n_stuffer_free);

    RESULT_GUARD_POSIX(s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob));

    struct s2n_blob asn1_cert = { 0 };
    RESULT_GUARD(s2n_x509_validator_read_asn1_cert(&cert_chain_in_stuffer, &asn1_cert));

    RESULT_ENSURE(s2n_asn1der_to_public_key_and_type(public_key, pkey_type, &asn1_cert) == 0,
            S2N_ERR_CERT_UNTRUSTED);

    /* certificate extensions is a field in TLS 1.3 - https://tools.ietf.org/html/rfc8446#section-4.4.2 */
    if (conn->actual_protocol_version >= S2N_TLS13) {
        s2n_parsed_extensions_list parsed_extensions_list = { 0 };
        RESULT_GUARD_POSIX(s2n_extension_list_parse(&cert_chain_in_stuffer, &parsed_extensions_list));

        *first_certificate_extensions = parsed_extensions_list;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_validate_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len, s2n_pkey_type *pkey_type, struct s2n_pkey *public_key_out) {
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    if (validator->state == INIT) {
        RESULT_GUARD(s2n_x509_validator_process_cert_chain(validator, conn, cert_chain_in, cert_chain_len));
    }

    if (validator->state == READY_TO_VERIFY) {
        RESULT_GUARD(s2n_x509_validator_verify_cert_chain(validator, conn));
    }

    DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
    s2n_pkey_zero_init(&public_key);
    s2n_parsed_extensions_list first_certificate_extensions = { 0 };
    RESULT_GUARD(s2n_x509_validator_read_leaf_info(conn, cert_chain_in, cert_chain_len, &public_key, pkey_type,
            &first_certificate_extensions));

    if (conn->actual_protocol_version >= S2N_TLS13) {
        /* Only process certificate extensions received in the first certificate. Extensions received in all other
         * certificates are ignored.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.4.2
         *# If an extension applies to the entire chain, it SHOULD be included in
         *# the first CertificateEntry.
         */
        RESULT_GUARD_POSIX(s2n_extension_list_process(S2N_EXTENSION_LIST_CERTIFICATE, conn, &first_certificate_extensions));
    }

    *public_key_out = public_key;

    /* Reset the old struct, so we don't clean up public_key_out */
    s2n_pkey_zero_init(&public_key);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_validate_cert_stapled_ocsp_response(struct s2n_x509_validator *validator,
        struct s2n_connection *conn, const uint8_t *ocsp_response_raw, uint32_t ocsp_response_length) {

    if (validator->skip_cert_validation || !validator->check_stapled_ocsp) {
        validator->state = OCSP_VALIDATED;
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE(validator->state == VALIDATED, S2N_ERR_INVALID_CERT_STATE);

#if !S2N_OCSP_STAPLING_SUPPORTED
    /* Default to safety */
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
#else

    RESULT_ENSURE_REF(ocsp_response_raw);

    DEFER_CLEANUP(OCSP_RESPONSE *ocsp_response = d2i_OCSP_RESPONSE(NULL, &ocsp_response_raw, ocsp_response_length),
                  OCSP_RESPONSE_free_pointer);
    RESULT_ENSURE(ocsp_response != NULL, S2N_ERR_INVALID_OCSP_RESPONSE);

    int ocsp_status = OCSP_response_status(ocsp_response);
    RESULT_ENSURE(ocsp_status == OCSP_RESPONSE_STATUS_SUCCESSFUL, S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(OCSP_BASICRESP *basic_response = OCSP_response_get1_basic(ocsp_response), OCSP_BASICRESP_free_pointer);
    RESULT_ENSURE(basic_response != NULL, S2N_ERR_INVALID_OCSP_RESPONSE);

    /* X509_STORE_CTX_get0_chain() is better because it doesn't return a copy. But it's not available for Openssl 1.0.2.
     * Therefore, we call this variant and clean it up at the end of the function.
     * See the comments here:
     * https://www.openssl.org/docs/man1.0.2/man3/X509_STORE_CTX_get1_chain.html
     */
    DEFER_CLEANUP(STACK_OF(X509) *cert_chain = X509_STORE_CTX_get1_chain(validator->store_ctx),
            s2n_openssl_x509_stack_pop_free);
    RESULT_ENSURE_REF(cert_chain);

    const int certs_in_chain = sk_X509_num(cert_chain);
    RESULT_ENSURE(certs_in_chain > 0, S2N_ERR_NO_CERT_FOUND);

    /* leaf is the top: not the bottom. */
    X509 *subject = sk_X509_value(cert_chain, 0);
    X509 *issuer = NULL;
    /* find the issuer in the chain. If it's not there. Fail everything. */
    for (int i = 0; i < certs_in_chain; ++i) {
        X509 *issuer_candidate = sk_X509_value(cert_chain, i);
        const int issuer_value = X509_check_issued(issuer_candidate, subject);

        if (issuer_value == X509_V_OK) {
            issuer = issuer_candidate;
            break;
        }
    }
    RESULT_ENSURE(issuer != NULL, S2N_ERR_CERT_UNTRUSTED);

    /* Important: this checks that the stapled ocsp response CAN be verified, not that it has been verified. */
    const int ocsp_verify_res = OCSP_basic_verify(basic_response, cert_chain, validator->trust_store->trust_store, 0);
    RESULT_GUARD_OSSL(ocsp_verify_res, S2N_ERR_CERT_UNTRUSTED);

    /* do the crypto checks on the response.*/
    int status = 0;
    int reason = 0;

    /* sha1 is the only supported OCSP digest */
    OCSP_CERTID *cert_id = OCSP_cert_to_id(EVP_sha1(), subject, issuer);
    RESULT_ENSURE_REF(cert_id);

    ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd;
    /* Actual verification of the response */
    const int ocsp_resp_find_status_res = OCSP_resp_find_status(basic_response, cert_id, &status, &reason, &revtime, &thisupd, &nextupd);
    OCSP_CERTID_free(cert_id);
    RESULT_GUARD_OSSL(ocsp_resp_find_status_res, S2N_ERR_CERT_UNTRUSTED);

    uint64_t this_update = 0;
    RESULT_GUARD(s2n_asn1_time_to_nano_since_epoch_ticks((const char *) thisupd->data,
            (uint32_t) thisupd->length, &this_update));

    uint64_t next_update = 0;
    if (nextupd) {
        RESULT_GUARD(s2n_asn1_time_to_nano_since_epoch_ticks((const char *) nextupd->data,
                (uint32_t) nextupd->length, &next_update));
    } else {
        next_update = this_update + DEFAULT_OCSP_NEXT_UPDATE_PERIOD;
    }

    uint64_t current_time = 0;
    RESULT_GUARD_POSIX(conn->config->wall_clock(conn->config->sys_clock_ctx, &current_time));

    RESULT_ENSURE(current_time >= this_update, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(current_time <= next_update, S2N_ERR_CERT_EXPIRED);

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            validator->state = OCSP_VALIDATED;
            return S2N_RESULT_OK;
        case V_OCSP_CERTSTATUS_REVOKED:
            RESULT_BAIL(S2N_ERR_CERT_REVOKED);
        default:
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }
#endif /* S2N_OCSP_STAPLING_SUPPORTED */
}

S2N_RESULT s2n_validate_certificate_signature(struct s2n_connection *conn, X509 *x509_cert)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(x509_cert);

    const struct s2n_security_policy *security_policy;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &security_policy));

    if (security_policy->certificate_signature_preferences == NULL) {
        return S2N_RESULT_OK;
    }

    X509_NAME *issuer_name = X509_get_issuer_name(x509_cert);
    RESULT_ENSURE_REF(issuer_name);

    X509_NAME *subject_name = X509_get_subject_name(x509_cert);
    RESULT_ENSURE_REF(subject_name);

    /* Do not validate any self-signed certificates */
    if (X509_NAME_cmp(issuer_name, subject_name) == 0) {
        return S2N_RESULT_OK;
    }

    RESULT_GUARD(s2n_validate_sig_scheme_supported(conn, x509_cert, security_policy->certificate_signature_preferences));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_validate_sig_scheme_supported(struct s2n_connection *conn, X509 *x509_cert, const struct s2n_signature_preferences *cert_sig_preferences)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(x509_cert);
    RESULT_ENSURE_REF(cert_sig_preferences);

    int nid = 0;

    #if defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x02070000f)
        RESULT_ENSURE_REF(x509_cert->sig_alg);
        nid = OBJ_obj2nid(x509_cert->sig_alg->algorithm);
    #else
        nid = X509_get_signature_nid(x509_cert);
    #endif

    for (size_t i = 0; i < cert_sig_preferences->count; i++) {

        if (cert_sig_preferences->signature_schemes[i]->libcrypto_nid == nid) {
            /* SHA-1 algorithms are not supported in certificate signatures in TLS1.3 */
            RESULT_ENSURE(!(conn->actual_protocol_version >= S2N_TLS13 &&
                    cert_sig_preferences->signature_schemes[i]->hash_alg == S2N_HASH_SHA1), S2N_ERR_CERT_UNTRUSTED);

            return S2N_RESULT_OK;
        }
    }

    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

bool s2n_x509_validator_is_cert_chain_validated(const struct s2n_x509_validator *validator)
{
    return validator && (validator->state == VALIDATED || validator->state == OCSP_VALIDATED);
}
