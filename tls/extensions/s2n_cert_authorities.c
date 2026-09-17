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
#include "tls/extensions/s2n_cert_authorities.h"

#include <openssl/x509.h>

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_openssl_x509.h"
#include "utils/s2n_safety.h"

bool s2n_cert_authorities_supported_from_trust_store()
{
#if S2N_LIBCRYPTO_SUPPORTS_X509_STORE_LIST
    return true;
#else
    return false;
#endif
}

static S2N_RESULT s2n_cert_authorities_set_from_trust_store(struct s2n_config *config)
{
    RESULT_ENSURE_REF(config);

    if (!config->trust_store.trust_store) {
        return S2N_RESULT_OK;
    }

#if S2N_LIBCRYPTO_SUPPORTS_X509_STORE_LIST
    DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&output, 256));

    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(config->trust_store.trust_store);
    RESULT_ENSURE(objects, S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    int objects_count = sk_X509_OBJECT_num(objects);
    RESULT_ENSURE(objects_count >= 0, S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    for (int i = 0; i < objects_count; i++) {
        X509_OBJECT *x509_object = sk_X509_OBJECT_value(objects, i);
        RESULT_ENSURE(x509_object, S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

        X509 *cert = X509_OBJECT_get0_X509(x509_object);
        if (cert == NULL) {
            /* X509_OBJECTs can also be CRLs, resulting in NULL here. Skip. */
            continue;
        }

        X509_NAME *name = X509_get_subject_name(cert);
        RESULT_ENSURE(name, S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

        const uint8_t *name_bytes = NULL;
        size_t name_size = 0;
        RESULT_GUARD_OSSL(X509_NAME_get0_der(name, &name_bytes, &name_size),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&output, name_size));
        RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&output, name_bytes, name_size));
        RESULT_ENSURE(s2n_stuffer_data_available(&output) <= S2N_CERT_AUTHORITIES_MAX_SIZE,
                S2N_ERR_TOO_MANY_CAS);
    }

    RESULT_GUARD_POSIX(s2n_stuffer_extract_blob(&output, &config->cert_authorities));
    return S2N_RESULT_OK;
#else
    RESULT_BAIL(S2N_ERR_API_UNSUPPORTED_BY_LIBCRYPTO);
#endif
}

int s2n_config_set_cert_authorities_from_trust_store(struct s2n_config *config)
{
    POSIX_ENSURE_REF(config);
    POSIX_ENSURE(!config->trust_store.loaded_system_certs, S2N_ERR_INVALID_STATE);
    POSIX_GUARD_RESULT(s2n_cert_authorities_set_from_trust_store(config));
    return S2N_SUCCESS;
}

int s2n_cert_authorities_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    /* The certificate_authorities extension may be sent by a server in the
     * CertificateRequest message or by a client in the ClientHello message.
     * See https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4 */
    struct s2n_blob *cert_authorities = &conn->config->cert_authorities;
    POSIX_GUARD(s2n_stuffer_write_uint16(out, cert_authorities->size));
    POSIX_GUARD(s2n_stuffer_write(out, cert_authorities));
    return S2N_SUCCESS;
}

int s2n_cert_authorities_recv(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);

    /* A client reads the CA list from a server's CertificateRequest so that
     * the cert_request_cb callback can use it to select a client certificate.
     * Only allocate the buffer if that callback is set, to save time and
     * memory for other customers.
     *
     * A server reads the CA list from a client's ClientHello so that it can
     * choose which server certificate chain to send. Only store it when more
     * than one certificate chain is configured; with a single chain the server
     * always sends that chain, so parsing the list would be wasted work.
     */
    bool store_for_client = (conn->mode == S2N_CLIENT && conn->config->cert_request_cb);
    bool store_for_server = (conn->mode == S2N_SERVER
            && s2n_config_get_num_default_certs(conn->config) > 1);
    if (store_for_client || store_for_server) {
        uint16_t length = 0;
        POSIX_GUARD(s2n_stuffer_read_uint16(in, &length));
        POSIX_GUARD(s2n_stuffer_extract_blob(in, &conn->cert_authorities));
        POSIX_ENSURE_EQ(conn->cert_authorities.size, length);
    }

    return S2N_SUCCESS;
}

/* Compare a single certificate's issuer and subject distinguished names against
 * the list of CA names advertised by the peer in the certificate_authorities
 * extension. Returns true (via *match) if either name is present in the list. */
static S2N_RESULT s2n_cert_authorities_cert_matches(struct s2n_blob *ca_names,
        struct s2n_cert *cert, bool *match)
{
    RESULT_ENSURE_REF(ca_names);
    RESULT_ENSURE_REF(cert);
    RESULT_ENSURE_REF(match);
    *match = false;

    DEFER_CLEANUP(X509 *x509 = NULL, X509_free_pointer);
    RESULT_GUARD(s2n_openssl_x509_parse(&cert->raw, &x509));
    RESULT_ENSURE_REF(x509);

    /* Collect the DER encodings of the certificate's issuer and subject names.
     * A certificate is a match if the peer advertised the issuer of this cert
     * (this cert was issued by a trusted CA) or the subject of this cert (this
     * cert is itself one of the advertised CAs, e.g. a CA in the chain). */
    const uint8_t *names[2] = { 0 };
    size_t name_sizes[2] = { 0 };
    X509_NAME *issuer = X509_get_issuer_name(x509);
    X509_NAME *subject = X509_get_subject_name(x509);
    if (issuer != NULL) {
        RESULT_GUARD_OSSL(X509_NAME_get0_der(issuer, &names[0], &name_sizes[0]),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
    }
    if (subject != NULL) {
        RESULT_GUARD_OSSL(X509_NAME_get0_der(subject, &names[1], &name_sizes[1]),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
    }

    /* Iterate over the advertised CA names: each entry is uint16 length
     * followed by the DER encoding of an X509_NAME. */
    struct s2n_stuffer iterator = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&iterator, ca_names));
    while (s2n_stuffer_data_available(&iterator) > 0) {
        uint16_t name_len = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&iterator, &name_len));
        uint8_t *name = s2n_stuffer_raw_read(&iterator, name_len);
        RESULT_ENSURE_REF(name);

        for (size_t i = 0; i < s2n_array_len(names); i++) {
            if (names[i] != NULL && name_sizes[i] == name_len
                    && memcmp(names[i], name, name_len) == 0) {
                *match = true;
                return S2N_RESULT_OK;
            }
        }
    }

    return S2N_RESULT_OK;
}

/* Returns true (via *match) if any certificate in the given chain is issued by,
 * or is itself, one of the CAs advertised by the peer in the
 * certificate_authorities extension. */
S2N_RESULT s2n_cert_authorities_chain_matches(struct s2n_connection *conn,
        struct s2n_cert_chain_and_key *chain_and_key, bool *match)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(chain_and_key);
    RESULT_ENSURE_REF(match);
    *match = false;

    /* No CA names were advertised, so there is nothing to match against. */
    if (conn->cert_authorities.size == 0) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE_REF(chain_and_key->cert_chain);
    struct s2n_cert *cert = chain_and_key->cert_chain->head;
    while (cert != NULL) {
        RESULT_GUARD(s2n_cert_authorities_cert_matches(&conn->cert_authorities, cert, match));
        if (*match) {
            return S2N_RESULT_OK;
        }
        cert = cert->next;
    }

    return S2N_RESULT_OK;
}

static bool s2n_cert_authorities_should_send(struct s2n_connection *conn)
{
    return conn && conn->config && conn->config->cert_authorities.size > 0;
}

const s2n_extension_type s2n_cert_authorities_extension = {
    .iana_value = TLS_EXTENSION_CERT_AUTHORITIES,
    .minimum_version = S2N_TLS13,
    .is_response = false,
    .send = s2n_cert_authorities_send,
    .should_send = s2n_cert_authorities_should_send,
    /*
     *= https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4
     *# The "certificate_authorities" extension is used to indicate the
     *# certificate authorities (CAs) which an endpoint supports and which
     *# SHOULD be used by the receiving endpoint to guide certificate
     *# selection.
     */
    .recv = s2n_cert_authorities_recv,
    .if_missing = s2n_extension_noop_if_missing,
};
