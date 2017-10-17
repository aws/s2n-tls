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

#include "tls/s2n_x509_validator.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_pkey.h"
#include "crypto/s2n_certificate.h"

#include "openssl/pem.h"
#include "openssl/ocsp.h"

void s2n_x509_trust_store_init(struct s2n_x509_trust_store *store) {
    store->trust_store = NULL;
}

uint8_t s2n_x509_trust_store_has_certs(struct s2n_x509_trust_store *store) {
    return store->trust_store ? 1 : 0;
}

int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_file) {
    s2n_x509_trust_store_cleanup(store);

    store->trust_store = X509_STORE_new();

    BIO *store_file_bio = BIO_new_file(ca_file, "r");

    int err_code = 0;

    if(store_file_bio) {
        X509 *trust_cert = NULL;
        while((trust_cert = PEM_read_bio_X509(store_file_bio, NULL, 0, NULL))) {
            X509_STORE_add_cert(store->trust_store, trust_cert);
        }

        BIO_free(store_file_bio);
        return 0;
    }

    s2n_x509_trust_store_cleanup(store);
    return err_code;
}

void s2n_x509_trust_store_cleanup(struct s2n_x509_trust_store *store) {
    if(store->trust_store) {
        X509_STORE_free(store->trust_store);
        store->trust_store = NULL;
    }
}

static uint8_t default_verify_host(const char *host_name, size_t len, void *data) {
    return 1;
}

int s2n_x509_validator_init_no_checks(struct s2n_x509_validator *validator) {
    validator->trust_store = NULL;
    validator->verify_host_fn = NULL;
    validator->validation_ctx = NULL;
    validator->cert_chain = NULL;
    validator->validate_certificates = 0;

    validator->current_step = S2N_X509_NOT_STARTED;
    return 0;
}

int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, verify_host verify_host_fn, void *verify_ctx) {
    notnull_check(trust_store);
    validator->trust_store = trust_store;

    validator->validate_certificates = 1;

    validator->verify_host_fn = default_verify_host;

    if(verify_host_fn) {
        validator->verify_host_fn = verify_host_fn;
    }

    validator->validation_ctx = verify_ctx;

    validator->cert_chain = NULL;
    if(validator->trust_store->trust_store) {
        validator->cert_chain = sk_X509_new_null();
    }

    validator->current_step = S2N_X509_NOT_STARTED;
    return 0;
}

void s2n_x509_validator_cleanup(struct s2n_x509_validator *validator) {
    if(validator->cert_chain) {
        X509 *cert = NULL;
        while ((cert = sk_X509_pop(validator->cert_chain))) {
            X509_free(cert);
        }

        sk_X509_free(validator->cert_chain);
    }

    validator->trust_store = NULL;
    validator->verify_host_fn = NULL;
    validator->validation_ctx = NULL;
    validator->validate_certificates = 0;
    validator->current_step = S2N_X509_NOT_STARTED;
}

static uint8_t verify_host_information(struct s2n_x509_validator *validator, X509 *public_cert)
{
    uint8_t verified = 0;
    //host name checks here.
    STACK_OF(GENERAL_NAME) *names_list = X509_get_ext_d2i(public_cert, NID_subject_alt_name, NULL, NULL);
    GENERAL_NAME *current_name = NULL;
    while (!verified && names_list && (current_name = sk_GENERAL_NAME_pop(names_list))) {
        const char *name = (const char *) M_ASN1_STRING_data(current_name->d.ia5);
        size_t name_len = (size_t) M_ASN1_STRING_length(current_name->d.ia5);

        verified = validator->verify_host_fn(name, name_len, validator->validation_ctx);
    }

    GENERAL_NAMES_free(names_list);

    if(!verified) {
        X509_NAME *subject_name = X509_get_subject_name(public_cert);
        if (subject_name) {
            int j = 0, i = -1;
            while ((j = X509_NAME_get_index_by_NID(subject_name, NID_commonName, i)) >= 0) {
                i = j;
            }

            if (i >= 0) {
                ASN1_STRING *common_name =
                        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject_name, i));

                if (common_name) {
                    char peer_cn[255];
                    static size_t peer_cn_size = sizeof(peer_cn);
                    memset_check(&peer_cn, 0, peer_cn_size);
                    if (ASN1_STRING_type(common_name) == V_ASN1_UTF8STRING) {
                        size_t len = (size_t) ASN1_STRING_length(common_name);
                        //save space for the null terminator
                        len = len > sizeof(peer_cn) - 1 ? sizeof(peer_cn) - 1 : len;

                        memcpy_check(peer_cn, ASN1_STRING_data(common_name), len);
                        verified = validator->verify_host_fn(peer_cn, len, validator->validation_ctx);
                    }
                }
            }
            else {
                return 0;
            }
        }
    }

    return verified;
}

s2n_cert_validation_code s2n_x509_validator_validate_cert_chain(struct s2n_x509_validator *validator, uint8_t *cert_chain_in,
                                             uint32_t cert_chain_len,
                                             struct s2n_cert_public_key *public_key_out) {

    if(validator->validate_certificates && !s2n_x509_trust_store_has_certs(validator->trust_store)) {
       return S2N_CERT_ERR_UNTRUSTED;
    }

    X509_STORE_CTX *ctx = NULL;
    X509 *last_in_chain;
    X509 *public_key;

    struct s2n_blob cert_chain_blob = { .data = cert_chain_in, .size = cert_chain_len};
    struct s2n_stuffer cert_chain_in_stuffer;
    if (s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob) < 0) {
        return S2N_CERT_ERR_INVALID;
    }
    if (s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob) < 0) {
        return S2N_CERT_ERR_INVALID;
    }

    uint32_t certificate_count = 0;

    s2n_cert_validation_code err_code = S2N_CERT_OK;

    while (s2n_stuffer_data_available(&cert_chain_in_stuffer)) {
        uint32_t certificate_size;

        if (s2n_stuffer_read_uint24(&cert_chain_in_stuffer, &certificate_size) < 0) {
            err_code = S2N_CERT_ERR_INVALID;
            goto clean_up;
        }

        if (certificate_size == 0 || certificate_size > s2n_stuffer_data_available(&cert_chain_in_stuffer) ) {
            err_code = S2N_CERT_ERR_INVALID;
            goto clean_up;
        }

        struct s2n_blob asn1cert;
        asn1cert.data = s2n_stuffer_raw_read(&cert_chain_in_stuffer, certificate_size);
        asn1cert.size = certificate_size;
        if (asn1cert.data == NULL) {
            err_code = S2N_CERT_ERR_INVALID;
            goto clean_up;
        }

        const uint8_t *data = asn1cert.data;

        X509 *server_cert = NULL;
        if(validator->validate_certificates) {
            server_cert = d2i_X509(NULL, &data, asn1cert.size);

            if(!server_cert) {
                err_code = S2N_CERT_ERR_INVALID;
                goto clean_up;
            }

            if(!sk_X509_push(validator->cert_chain, server_cert)) {
                X509_free(server_cert);
                err_code = S2N_CERT_ERR_INVALID;
                goto clean_up;
            }
        }

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            /* Assume that the asn1cert is an RSA Cert */
            if (s2n_asn1der_to_public_key(&public_key_out->pkey, &asn1cert) < 0) {
                err_code = S2N_CERT_ERR_INVALID;
                goto clean_up;
            }
            if (s2n_cert_public_key_set_cert_type(public_key_out, S2N_CERT_TYPE_RSA_SIGN) < 0){
                err_code = S2N_CERT_ERR_INVALID;
                goto clean_up;
            }

            public_key = server_cert;
        }

        last_in_chain = server_cert;

        certificate_count++;
    }

    if (certificate_count < 1) {
        err_code = S2N_CERT_ERR_INVALID;
        goto clean_up;
    }

    if (validator->validate_certificates && validator->verify_host_fn && !verify_host_information(validator, public_key)) {
        err_code = S2N_CERT_ERR_UNTRUSTED;
        goto clean_up;
    }

    if(validator->validate_certificates) {
        ctx = X509_STORE_CTX_new();
        int op_code = X509_STORE_CTX_init(ctx, validator->trust_store->trust_store, last_in_chain, validator->cert_chain);

        if (op_code <= 0) {
            err_code = S2N_CERT_ERR_INVALID;
            goto clean_up;
        }

        op_code = X509_verify_cert(ctx);

        if (op_code <= 0) {
            op_code = X509_STORE_CTX_get_error(ctx);

            X509_STORE_CTX_cleanup(ctx);
            err_code = S2N_CERT_ERR_UNTRUSTED;
            goto clean_up;
        }
    }

    clean_up:
    if(ctx) {
        X509_STORE_CTX_cleanup(ctx);
    }
    return err_code;
}

s2n_cert_validation_code s2n_x509_validator_validate_cert_stapled_ocsp_response(struct s2n_x509_validator *validator, const uint8_t *ocsp_response_raw, size_t ocsp_response_length) {
    if(!validator->validate_certificates) {
        return S2N_CERT_OK;
    }

    OCSP_RESPONSE *ocsp_response = NULL;
    OCSP_BASICRESP *basic_response = NULL;

    s2n_cert_validation_code ret_val = S2N_CERT_OK;

    if(!ocsp_response_raw) {
        return S2N_CERT_ERR_INVALID;
    }

    ocsp_response = d2i_OCSP_RESPONSE(NULL, &ocsp_response_raw, ocsp_response_length);

    if(!ocsp_response) {
        ret_val = S2N_CERT_ERR_INVALID;
        goto clean_up;
    }

    int ocsp_status = OCSP_response_status(ocsp_response);

    if(ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ret_val = S2N_CERT_ERR_INVALID;
        goto clean_up;
    }

    basic_response = OCSP_response_get1_basic(ocsp_response);
    if(!basic_response) {
        ret_val = S2N_CERT_ERR_INVALID;
        goto clean_up;
    }

    if(!OCSP_basic_verify(basic_response, validator->cert_chain, validator->trust_store->trust_store, 0)) {
        ret_val = S2N_CERT_ERR_EXPIRED;
        goto clean_up;
    }

    clean_up:
    if(basic_response) {
        OCSP_BASICRESP_free(basic_response);
    }

    if(ocsp_response) {
        OCSP_RESPONSE_free(ocsp_response);
    }

    return ret_val;
}
