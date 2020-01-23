/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "utils/s2n_safety.h"
#include "utils/s2n_rfc5952.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "extensions/s2n_certificate_extensions.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/asn1.h>

#if !defined(OPENSSL_IS_BORINGSSL)
#include <openssl/ocsp.h>
#endif

/* one day, boringssl, may add ocsp stapling support. Let's future proof this a bit by grabbing a definition
 * that would have to be there when they add support */
#if defined(OPENSSL_IS_BORINGSSL) && !defined(OCSP_RESPONSE_STATUS_SUCCESSFUL)
#define S2N_OCSP_STAPLING_SUPPORTED 0
#else
#define S2N_OCSP_STAPLING_SUPPORTED 1
#endif /* defined(OPENSSL_IS_BORINGSSL) && !defined(OCSP_RESPONSE_STATUS_SUCCESSFUL) */

/* our friends at openssl love to make backwards incompatible changes */
#if !defined(LIBRESSL_VERSION_NUMBER) && S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0)
#define OCSP_GET_CERTS(a) OCSP_resp_get0_certs(a)
#else
#define OCSP_GET_CERTS(a) a->certs
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
        notnull_check(store->trust_store);
    }

    int err_code = X509_STORE_set_default_paths(store->trust_store);
    if (!err_code) {
        s2n_x509_trust_store_wipe(store);
        S2N_ERROR(S2N_ERR_X509_TRUST_STORE);
    }

    X509_STORE_set_flags(store->trust_store, X509_VP_FLAG_DEFAULT);

    return 0;
}

int s2n_x509_trust_store_add_pem(struct s2n_x509_trust_store *store, const char *pem)
{
    notnull_check(store);
    notnull_check(pem);

    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
    }

    DEFER_CLEANUP(struct s2n_stuffer pem_in_stuffer = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer der_out_stuffer = {0}, s2n_stuffer_free);

    GUARD(s2n_stuffer_alloc_ro_from_string(&pem_in_stuffer, pem));
    GUARD(s2n_stuffer_growable_alloc(&der_out_stuffer, 2048));

    do {
        DEFER_CLEANUP(struct s2n_blob next_cert = {0}, s2n_free);

        GUARD(s2n_stuffer_certificate_from_pem(&pem_in_stuffer, &der_out_stuffer));
        GUARD(s2n_alloc(&next_cert, s2n_stuffer_data_available(&der_out_stuffer)));
        GUARD(s2n_stuffer_read(&der_out_stuffer, &next_cert));

        const uint8_t *data = next_cert.data;
        DEFER_CLEANUP(X509 *ca_cert = d2i_X509(NULL, &data, next_cert.size), X509_free_pointer);
        S2N_ERROR_IF(ca_cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

        GUARD_OSSL(X509_STORE_add_cert(store->trust_store, ca_cert), S2N_ERR_DECODE_CERTIFICATE);
    } while (s2n_stuffer_data_available(&pem_in_stuffer));

    return 0;
}

int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_pem_filename, const char *ca_dir) {

    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
        notnull_check(store->trust_store);
    }

    int err_code = X509_STORE_load_locations(store->trust_store, ca_pem_filename, ca_dir);
    if (!err_code) {
        s2n_x509_trust_store_wipe(store);
        S2N_ERROR(S2N_ERR_X509_TRUST_STORE);
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
    validator->trust_store = NULL;
    validator->cert_chain = NULL;
    validator->skip_cert_validation = 1;
    validator->check_stapled_ocsp = 0;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;

    return 0;
}

int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, uint8_t check_ocsp) {
    notnull_check(trust_store);
    validator->trust_store = trust_store;

    validator->skip_cert_validation = 0;
    validator->check_stapled_ocsp = check_ocsp;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;

    validator->cert_chain = NULL;
    if (validator->trust_store->trust_store) {
        validator->cert_chain = sk_X509_new_null();
    }

    return 0;
}

void s2n_x509_validator_wipe(struct s2n_x509_validator *validator) {
    if (validator->cert_chain) {
        sk_X509_pop_free(validator->cert_chain, X509_free);
        validator->cert_chain = NULL;
    }

    validator->trust_store = NULL;
    validator->skip_cert_validation = 0;
}

int s2n_x509_validator_set_max_chain_depth(struct s2n_x509_validator *validator, uint16_t max_depth) {
    notnull_check(validator);
    S2N_ERROR_IF(max_depth == 0, S2N_ERR_INVALID_ARGUMENT);

    validator->max_chain_depth = max_depth;
    return 0;
}

/*
 * For each name in the cert. Iterate them. Call the callback. If one returns true, then consider it validated,
 * if none of them return true, the cert is considered invalid.
 */
static uint8_t s2n_verify_host_information(struct s2n_x509_validator *validator, struct s2n_connection *conn, X509 *public_cert) {
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

            int parse_err = -1;
            s2n_stack_blob(address, INET6_ADDRSTRLEN + 1, INET6_ADDRSTRLEN + 1); 
            if (ip_addr_len == 4) {
                parse_err = s2n_inet_ntop(AF_INET, ip_addr, &address);                
            } else if (ip_addr_len == 16) {
                parse_err = s2n_inet_ntop(AF_INET6, ip_addr, &address);
            }

            /* strlen should be safe here since we made sure we were null terminated AND that inet_ntop succeeded */
            if (!parse_err) {
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
                    memset_check(&peer_cn, 0, peer_cn_size);
                    
                    /* X520CommonName allows the following ANSI string types per RFC 5280 Appendix A.1 */
                    if (ASN1_STRING_type(common_name) == V_ASN1_TELETEXSTRING || 
                        ASN1_STRING_type(common_name) == V_ASN1_PRINTABLESTRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_UNIVERSALSTRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_UTF8STRING ||
                        ASN1_STRING_type(common_name) == V_ASN1_BMPSTRING ) {

                        size_t len = (size_t) ASN1_STRING_length(common_name);

                        lte_check(len, sizeof(peer_cn) - 1);
                        memcpy_check(peer_cn, ASN1_STRING_data(common_name), len);
                        verified = conn->verify_host_fn(peer_cn, len, conn->data_for_verify_host);
                    }
                }
            }
        }
    }

    return verified;
}

s2n_cert_validation_code s2n_x509_validator_validate_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
                                                                uint8_t *cert_chain_in, uint32_t cert_chain_len,
                                                                s2n_pkey_type *pkey_type, struct s2n_pkey *public_key_out) {

    if (!validator->skip_cert_validation && !s2n_x509_trust_store_has_certs(validator->trust_store)) {
        return S2N_CERT_ERR_UNTRUSTED;
    }

    DEFER_CLEANUP(X509_STORE_CTX *ctx = NULL, X509_STORE_CTX_free_pointer);

    struct s2n_blob cert_chain_blob = {.data = cert_chain_in, .size = cert_chain_len};
    DEFER_CLEANUP(struct s2n_stuffer cert_chain_in_stuffer = {0}, s2n_stuffer_free);
    if (s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob) < 0) {
        return S2N_CERT_ERR_INVALID;
    }
    if (s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob) < 0) {
        return S2N_CERT_ERR_INVALID;
    }

    uint32_t certificate_count = 0;

    X509 *server_cert = NULL;

    DEFER_CLEANUP(struct s2n_pkey public_key = {0}, s2n_pkey_free);
    s2n_pkey_zero_init(&public_key);

    while (s2n_stuffer_data_available(&cert_chain_in_stuffer) && certificate_count < validator->max_chain_depth) {
        uint32_t certificate_size = 0;

        if (s2n_stuffer_read_uint24(&cert_chain_in_stuffer, &certificate_size) < 0) {
            return S2N_CERT_ERR_INVALID;
        }

        if (certificate_size == 0 || certificate_size > s2n_stuffer_data_available(&cert_chain_in_stuffer)) {
            return S2N_CERT_ERR_INVALID;
        }

        struct s2n_blob asn1cert = {0};
        asn1cert.size = certificate_size;
        asn1cert.data = s2n_stuffer_raw_read(&cert_chain_in_stuffer, certificate_size);
        if (asn1cert.data == NULL) {
            return S2N_CERT_ERR_INVALID;
        }

        const uint8_t *data = asn1cert.data;

        if (!validator->skip_cert_validation) {
            /* the cert is der encoded, just convert it. */
            server_cert = d2i_X509(NULL, &data, asn1cert.size);
            if (!server_cert) {
                return S2N_CERT_ERR_INVALID;
            }

            /* add the cert to the chain. */
            if (!sk_X509_push(validator->cert_chain, server_cert)) {
                X509_free(server_cert);
                return S2N_CERT_ERR_INVALID;
            }
         }

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            if (s2n_asn1der_to_public_key_and_type(&public_key, pkey_type, &asn1cert) < 0) {
                return S2N_CERT_ERR_INVALID;
            }
        }

        /* certificate extensions is a field in TLS 1.3 - https://tools.ietf.org/html/rfc8446#section-4.4.2 */
        if (conn->actual_protocol_version == S2N_TLS13) {
            uint16_t certificate_extensions_length = 0;
            S2N_ERROR_IF(2 > s2n_stuffer_data_available(&cert_chain_in_stuffer), S2N_ERR_BAD_MESSAGE);
            GUARD(s2n_stuffer_read_uint16(&cert_chain_in_stuffer, &certificate_extensions_length));
            S2N_ERROR_IF(certificate_extensions_length > s2n_stuffer_data_available(&cert_chain_in_stuffer), S2N_ERR_BAD_MESSAGE);

            if (certificate_extensions_length > 0) {
                struct s2n_blob extensions = {0};
                extensions.size = certificate_extensions_length;
                extensions.data = s2n_stuffer_raw_read(&cert_chain_in_stuffer, extensions.size);
                notnull_check(extensions.data);
                
                /* RFC 8446: if an extension applies to the entire chain, it SHOULD be included in the first CertificateEntry */
                if (certificate_count == 0) {
                    GUARD(s2n_certificate_extensions_parse(conn, &extensions));
                }
            }
        }

        certificate_count++;
    }

    /* if this occurred we exceeded validator->max_chain_depth */
    if (!validator->skip_cert_validation && s2n_stuffer_data_available(&cert_chain_in_stuffer)) {
        return S2N_CERT_ERR_MAX_CHAIN_DEPTH_EXCEEDED;
    }

    if (certificate_count < 1) {
        return S2N_CERT_ERR_INVALID;
    }


    if (!validator->skip_cert_validation) {
        X509 *leaf = sk_X509_value(validator->cert_chain, 0);
        if (!leaf) {
            return S2N_CERT_ERR_INVALID;
        }

        if (conn->verify_host_fn && !s2n_verify_host_information(validator, conn, leaf)) {
            return S2N_CERT_ERR_UNTRUSTED;
        }

        /* now that we have a chain, get the store and check against it. */
        ctx = X509_STORE_CTX_new();

        int op_code = X509_STORE_CTX_init(ctx, validator->trust_store->trust_store, leaf,
                                          validator->cert_chain);

        if (op_code <= 0) {
            return S2N_CERT_ERR_INVALID;
        }

        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_depth(param, validator->max_chain_depth);


        uint64_t current_sys_time = 0;
        conn->config->wall_clock(conn->config->sys_clock_ctx, &current_sys_time);

        /* this wants seconds not nanoseconds */
        time_t current_time = (time_t)(current_sys_time / 1000000000);
        X509_STORE_CTX_set_time(ctx, 0, current_time);

        op_code = X509_verify_cert(ctx);

        if (op_code <= 0) {
            return S2N_CERT_ERR_UNTRUSTED;
        }
    }


    *public_key_out = public_key;

    /* Reset the old struct, so we don't clean up public_key_out */
    s2n_pkey_zero_init(&public_key);

    return S2N_CERT_OK;
}

s2n_cert_validation_code s2n_x509_validator_validate_cert_stapled_ocsp_response(struct s2n_x509_validator *validator,
                                                                                struct s2n_connection *conn,
                                                                                const uint8_t *ocsp_response_raw,
                                                                                uint32_t ocsp_response_length) {

    if (validator->skip_cert_validation || !validator->check_stapled_ocsp) {
        return S2N_CERT_OK;
    }

#if !S2N_OCSP_STAPLING_SUPPORTED
    /* Default to safety */
    return S2N_CERT_ERR_UNTRUSTED;
#else

    OCSP_RESPONSE *ocsp_response = NULL;
    OCSP_BASICRESP *basic_response = NULL;

    s2n_cert_validation_code ret_val = S2N_CERT_ERR_INVALID;

    if (!ocsp_response_raw) {
        return ret_val;
    }

    ocsp_response = d2i_OCSP_RESPONSE(NULL, &ocsp_response_raw, ocsp_response_length);

    if (!ocsp_response) {
        goto clean_up;
    }

    int ocsp_status = OCSP_response_status(ocsp_response);

    if (ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        goto clean_up;
    }

    basic_response = OCSP_response_get1_basic(ocsp_response);
    if (!basic_response) {
        goto clean_up;
    }

    int i;

    int certs_in_chain = sk_X509_num(validator->cert_chain);
    int certs_in_ocsp = sk_X509_num(OCSP_GET_CERTS(basic_response));

    if (certs_in_chain >= 2 && certs_in_ocsp >= 1) {
        X509 *responder = sk_X509_value(OCSP_GET_CERTS(basic_response), certs_in_ocsp - 1);

        /*check to see if one of the certs in the chain is an issuer of the cert in the ocsp response.*/
        /*if so it needs to be added to the OCSP verification chain.*/
        for (i = 0; i < certs_in_chain; i++) {
            X509 *issuer = sk_X509_value(validator->cert_chain, i);
            int issuer_value = X509_check_issued(issuer, responder);

            if (issuer_value == X509_V_OK) {
                if (!OCSP_basic_add1_cert(basic_response, issuer)) {
                    goto clean_up;
                }
            }
        }
    }

    int ocsp_verify_err = OCSP_basic_verify(basic_response, validator->cert_chain, validator->trust_store->trust_store, 0);
    /* do the crypto checks on the response.*/
    if (!ocsp_verify_err) {
        ret_val = S2N_CERT_ERR_EXPIRED;
        goto clean_up;
    }

    /* for each response check the timestamps and the status. */
    for (i = 0; i < OCSP_resp_count(basic_response); i++) {
        int status_reason;
        ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd;

        OCSP_SINGLERESP *single_response = OCSP_resp_get0(basic_response, i);
        if (!single_response) {
            goto clean_up;
        }

        ocsp_status = OCSP_single_get0_status(single_response, &status_reason, &revtime,
                                              &thisupd, &nextupd);

        uint64_t this_update = 0;
        int thisupd_err = s2n_asn1_time_to_nano_since_epoch_ticks((const char *) thisupd->data,
                                                                  (uint32_t) thisupd->length, &this_update);

        uint64_t next_update = 0;
        int nextupd_err = 0;
        if (nextupd) {
            nextupd_err = s2n_asn1_time_to_nano_since_epoch_ticks((const char *) nextupd->data,
                                                                  (uint32_t) nextupd->length, &next_update);
        } else {
            next_update = this_update + DEFAULT_OCSP_NEXT_UPDATE_PERIOD;
        }

        uint64_t current_time = 0;
        int current_time_err = conn->config->wall_clock(conn->config->sys_clock_ctx, &current_time);

        if (thisupd_err || nextupd_err || current_time_err) {
            ret_val = S2N_CERT_ERR_UNTRUSTED;
            goto clean_up;
        }

        if (current_time < this_update || current_time > next_update) {
            ret_val = S2N_CERT_ERR_EXPIRED;
            goto clean_up;
        }

        switch (ocsp_status) {
            case V_OCSP_CERTSTATUS_GOOD:
                break;

            case V_OCSP_CERTSTATUS_REVOKED:
                ret_val = S2N_CERT_ERR_REVOKED;
                goto clean_up;

            case V_OCSP_CERTSTATUS_UNKNOWN:
                goto clean_up;
            default:
                goto clean_up;
        }
    }

    ret_val = S2N_CERT_OK;

    clean_up:
    if (basic_response) {
        OCSP_BASICRESP_free(basic_response);
    }

    if (ocsp_response) {
        OCSP_RESPONSE_free(ocsp_response);
    }

    return ret_val;
#endif /* S2N_OCSP_STAPLING_SUPPORTED */
}

