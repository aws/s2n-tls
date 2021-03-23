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

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <s2n.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <string.h>
#include <strings.h>

#include "crypto/s2n_certificate.h"
#include "utils/s2n_array.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_connection.h"

int s2n_cert_set_cert_type(struct s2n_cert *cert, s2n_pkey_type pkey_type)
{
    POSIX_ENSURE_REF(cert);
    cert->pkey_type = pkey_type;
    POSIX_GUARD(s2n_pkey_setup_for_type(&cert->public_key, pkey_type));
    return 0;
}

int s2n_create_cert_chain_from_stuffer(struct s2n_cert_chain *cert_chain_out, struct s2n_stuffer *chain_in_stuffer)
{
    DEFER_CLEANUP(struct s2n_stuffer cert_out_stuffer = {0}, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_growable_alloc(&cert_out_stuffer, 2048));

    struct s2n_cert **insert = &cert_chain_out->head;
    uint32_t chain_size = 0;
    do {
        struct s2n_cert *new_node = NULL;

        if (s2n_stuffer_certificate_from_pem(chain_in_stuffer, &cert_out_stuffer) < 0) {
            if (chain_size == 0) {
                POSIX_BAIL(S2N_ERR_NO_CERTIFICATE_IN_PEM);
            }
            break;
        }
        struct s2n_blob mem = {0};
        POSIX_GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert)));
        new_node = (struct s2n_cert *)(void *)mem.data;

        if (s2n_alloc(&new_node->raw, s2n_stuffer_data_available(&cert_out_stuffer)) != S2N_SUCCESS) {
            POSIX_GUARD(s2n_free(&mem));
            S2N_ERROR_PRESERVE_ERRNO();
        }
        if (s2n_stuffer_read(&cert_out_stuffer, &new_node->raw) != S2N_SUCCESS) {
            POSIX_GUARD(s2n_free(&mem));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        /* Additional 3 bytes for the length field in the protocol */
        chain_size += new_node->raw.size + 3;
        new_node->next = NULL;
        *insert = new_node;
        insert = &new_node->next;
    } while (s2n_stuffer_data_available(chain_in_stuffer));

    /* Leftover data at this point means one of two things:
     * A bug in s2n's PEM parsing OR a malformed PEM in the user's chain.
     * Be conservative and fail instead of using a partial chain.
     */
    S2N_ERROR_IF(s2n_stuffer_data_available(chain_in_stuffer) > 0, S2N_ERR_INVALID_PEM);

    cert_chain_out->chain_size = chain_size;

    return 0;
}

int s2n_cert_chain_and_key_set_cert_chain_from_stuffer(struct s2n_cert_chain_and_key *cert_and_key, struct s2n_stuffer *chain_in_stuffer)
{
    return s2n_create_cert_chain_from_stuffer(cert_and_key->cert_chain, chain_in_stuffer);
}

int s2n_cert_chain_and_key_set_cert_chain(struct s2n_cert_chain_and_key *cert_and_key, const char *cert_chain_pem)
{
    struct s2n_stuffer chain_in_stuffer = {0};

    /* Turn the chain into a stuffer */
    POSIX_GUARD(s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, cert_chain_pem));
    int rc = s2n_cert_chain_and_key_set_cert_chain_from_stuffer(cert_and_key, &chain_in_stuffer);

    POSIX_GUARD(s2n_stuffer_free(&chain_in_stuffer));

    return rc;
}

int s2n_cert_chain_and_key_set_private_key(struct s2n_cert_chain_and_key *cert_and_key, const char *private_key_pem)
{
    DEFER_CLEANUP(struct s2n_stuffer key_in_stuffer = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer key_out_stuffer = {0}, s2n_stuffer_free);
    struct s2n_blob key_blob = {0};

    POSIX_GUARD(s2n_pkey_zero_init(cert_and_key->private_key));

    /* Put the private key pem in a stuffer */
    POSIX_GUARD(s2n_stuffer_alloc_ro_from_string(&key_in_stuffer, private_key_pem));
    POSIX_GUARD(s2n_stuffer_growable_alloc(&key_out_stuffer, strlen(private_key_pem)));

    /* Convert pem to asn1 and asn1 to the private key. Handles both PKCS#1 and PKCS#8 formats */
    POSIX_GUARD(s2n_stuffer_private_key_from_pem(&key_in_stuffer, &key_out_stuffer));
    key_blob.size = s2n_stuffer_data_available(&key_out_stuffer);
    key_blob.data = s2n_stuffer_raw_read(&key_out_stuffer, key_blob.size);
    POSIX_ENSURE_REF(key_blob.data);

    /* Get key type and create appropriate key context */
    POSIX_GUARD(s2n_asn1der_to_private_key(cert_and_key->private_key, &key_blob));

    return 0;
}

int s2n_cert_chain_and_key_set_ocsp_data(struct s2n_cert_chain_and_key *chain_and_key, const uint8_t *data, uint32_t length)
{
    POSIX_ENSURE_REF(chain_and_key);
    POSIX_GUARD(s2n_free(&chain_and_key->ocsp_status));
    if (data && length) {
        POSIX_GUARD(s2n_alloc(&chain_and_key->ocsp_status, length));
        POSIX_CHECKED_MEMCPY(chain_and_key->ocsp_status.data, data, length);
    }
    return 0;
}

int s2n_cert_chain_and_key_set_sct_list(struct s2n_cert_chain_and_key *chain_and_key, const uint8_t *data, uint32_t length)
{
    POSIX_ENSURE_REF(chain_and_key);
    POSIX_GUARD(s2n_free(&chain_and_key->sct_list));
    if (data && length) {
        POSIX_GUARD(s2n_alloc(&chain_and_key->sct_list, length));
        POSIX_CHECKED_MEMCPY(chain_and_key->sct_list.data, data, length);
    }
    return 0;
}

struct s2n_cert_chain_and_key *s2n_cert_chain_and_key_new(void)
{
    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_blob chain_and_key_mem, cert_chain_mem, pkey_mem;

    PTR_GUARD_POSIX(s2n_alloc(&chain_and_key_mem, sizeof(struct s2n_cert_chain_and_key)));
    chain_and_key = (struct s2n_cert_chain_and_key *)(void *)chain_and_key_mem.data;

    /* Allocate the memory for the chain and key */
    if (s2n_alloc(&cert_chain_mem, sizeof(struct s2n_cert_chain)) != S2N_SUCCESS) {
        goto cleanup;
    }
    chain_and_key->cert_chain = (struct s2n_cert_chain *)(void *)cert_chain_mem.data;

    if (s2n_alloc(&pkey_mem, sizeof(s2n_cert_private_key)) != S2N_SUCCESS) {
        goto cleanup;
    }
    chain_and_key->private_key = (s2n_cert_private_key *)(void *)pkey_mem.data;

    chain_and_key->cert_chain->head = NULL;
    if (s2n_pkey_zero_init(chain_and_key->private_key) != S2N_SUCCESS) {
        goto cleanup;
    }
    memset(&chain_and_key->ocsp_status, 0, sizeof(chain_and_key->ocsp_status));
    memset(&chain_and_key->sct_list, 0, sizeof(chain_and_key->sct_list));
    chain_and_key->cn_names = s2n_array_new(sizeof(struct s2n_blob));
    if (!chain_and_key->cn_names) {
        goto cleanup;
    }

    chain_and_key->san_names = s2n_array_new(sizeof(struct s2n_blob));
    if (!chain_and_key->san_names) {
        goto cleanup;
    }

    chain_and_key->context = NULL;

    return chain_and_key;
    cleanup:
        s2n_free(&pkey_mem);
        s2n_free(&cert_chain_mem);
        s2n_free(&chain_and_key_mem);
    return NULL;
}

DEFINE_POINTER_CLEANUP_FUNC(GENERAL_NAMES *, GENERAL_NAMES_free);

int s2n_cert_chain_and_key_load_sans(struct s2n_cert_chain_and_key *chain_and_key, X509 *x509_cert)
{
    POSIX_ENSURE_REF(chain_and_key->san_names);

    DEFER_CLEANUP(GENERAL_NAMES *san_names = X509_get_ext_d2i(x509_cert, NID_subject_alt_name, NULL, NULL), GENERAL_NAMES_free_pointer);
    if (san_names == NULL) {
        /* No SAN extension */
        return 0;
    }

    const int num_san_names = sk_GENERAL_NAME_num(san_names);
    for (int i = 0; i < num_san_names; i++) {
        GENERAL_NAME *san_name = sk_GENERAL_NAME_value(san_names, i);
        if (!san_name) {
            continue;
        }

        if (san_name->type == GEN_DNS) {
            /* Decoding isn't necessary here since a DNS SAN name is ASCII(type V_ASN1_IA5STRING) */
            unsigned char *san_str = san_name->d.dNSName->data;
            const size_t san_str_len = san_name->d.dNSName->length;
            struct s2n_blob *san_blob = NULL;
            POSIX_GUARD_RESULT(s2n_array_pushback(chain_and_key->san_names, (void **)&san_blob));
            if (!san_blob) {
                POSIX_BAIL(S2N_ERR_NULL_SANS);
            }

            if (s2n_alloc(san_blob, san_str_len)) {
                S2N_ERROR_PRESERVE_ERRNO();
            }

            POSIX_CHECKED_MEMCPY(san_blob->data, san_str, san_str_len);
            san_blob->size = san_str_len;
            /* normalize san_blob to lowercase */
            POSIX_GUARD(s2n_blob_char_to_lower(san_blob));
        }
    }

    return 0;
}

/* Parse CN names from the Subject of the leaf certificate. Technically there can by multiple CNs
 * in the Subject but practically very few certificates in the wild will have more than one CN.
 * Since the data for this certificate is coming from the application and not from an untrusted
 * source, we will try our best to parse all of the CNs.
 *
 * A recent CAB thread proposed removing support for multiple CNs:
 * https://cabforum.org/pipermail/public/2016-April/007242.html
 */

DEFINE_POINTER_CLEANUP_FUNC(unsigned char *, OPENSSL_free);

int s2n_cert_chain_and_key_load_cns(struct s2n_cert_chain_and_key *chain_and_key, X509 *x509_cert)
{
    POSIX_ENSURE_REF(chain_and_key->cn_names);

    X509_NAME *subject = X509_get_subject_name(x509_cert);
    if (!subject) {
        return 0;
    }

    int lastpos = -1;
    while((lastpos = X509_NAME_get_index_by_NID(subject, NID_commonName, lastpos)) >= 0) {
        X509_NAME_ENTRY *name_entry = X509_NAME_get_entry(subject, lastpos);
        if (!name_entry) {
            continue;
        }

        ASN1_STRING *asn1_str = X509_NAME_ENTRY_get_data(name_entry);
        if (!asn1_str) {
            continue;
        }

        /* We need to try and decode the CN since it may be encoded as unicode with a
         * direct ASCII equivalent. Any non ASCII bytes in the string will fail later when we
         * actually compare hostnames.
         */
        DEFER_CLEANUP(unsigned char *utf8_str, OPENSSL_free_pointer);
        const int utf8_out_len = ASN1_STRING_to_UTF8(&utf8_str, asn1_str);
        if (utf8_out_len < 0) {
            /* On failure, ASN1_STRING_to_UTF8 does not allocate any memory */
            continue;
        } else if (utf8_out_len == 0) {
            /* We still need to free memory here see https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7521 */
            OPENSSL_free(utf8_str);
        } else {
            struct s2n_blob *cn_name = NULL;
            POSIX_GUARD_RESULT(s2n_array_pushback(chain_and_key->cn_names, (void **)&cn_name));
            if (cn_name == NULL) {
                POSIX_BAIL(S2N_ERR_NULL_CN_NAME);
            }

            if (s2n_alloc(cn_name, utf8_out_len) < 0) {
                S2N_ERROR_PRESERVE_ERRNO();
            }
            POSIX_CHECKED_MEMCPY(cn_name->data, utf8_str, utf8_out_len);
            cn_name->size = utf8_out_len;
            /* normalize cn_name to lowercase */
            POSIX_GUARD(s2n_blob_char_to_lower(cn_name));
        }
    }

    return 0;
}

static int s2n_cert_chain_and_key_set_names(struct s2n_cert_chain_and_key *chain_and_key, struct s2n_blob *leaf_bytes)
{
    const unsigned char *leaf_der = leaf_bytes->data;
    X509 *cert = d2i_X509(NULL, &leaf_der, leaf_bytes->size);
    if (!cert) {
        POSIX_BAIL(S2N_ERR_INVALID_PEM);
    }

    POSIX_GUARD(s2n_cert_chain_and_key_load_sans(chain_and_key, cert));
    /* For current use cases, we *could* avoid populating the common names if any sans were loaded in
     * s2n_cert_chain_and_key_load_sans. Let's unconditionally populate this field to avoid surprises
     * in the future.
     */
    POSIX_GUARD(s2n_cert_chain_and_key_load_cns(chain_and_key, cert));

    X509_free(cert);
    return 0;
}

int s2n_cert_chain_and_key_load_pem(struct s2n_cert_chain_and_key *chain_and_key, const char *chain_pem, const char *private_key_pem)
{
    POSIX_ENSURE_REF(chain_and_key);

    POSIX_GUARD(s2n_cert_chain_and_key_set_cert_chain(chain_and_key, chain_pem));
    POSIX_GUARD(s2n_cert_chain_and_key_set_private_key(chain_and_key, private_key_pem));

    /* Parse the leaf cert for the public key and certificate type */
    DEFER_CLEANUP(struct s2n_pkey public_key = {0}, s2n_pkey_free);
    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
    POSIX_GUARD(s2n_asn1der_to_public_key_and_type(&public_key, &pkey_type, &chain_and_key->cert_chain->head->raw));
    S2N_ERROR_IF(pkey_type == S2N_PKEY_TYPE_UNKNOWN, S2N_ERR_CERT_TYPE_UNSUPPORTED);
    POSIX_GUARD(s2n_cert_set_cert_type(chain_and_key->cert_chain->head, pkey_type));

    /* Validate the leaf cert's public key matches the provided private key */
    POSIX_GUARD(s2n_pkey_match(&public_key, chain_and_key->private_key));

    /* Populate name information from the SAN/CN for the leaf certificate */
    POSIX_GUARD(s2n_cert_chain_and_key_set_names(chain_and_key, &chain_and_key->cert_chain->head->raw));

    return 0;
}

int s2n_cert_chain_and_key_free(struct s2n_cert_chain_and_key *cert_and_key)
{
    if (cert_and_key == NULL) {
        return 0;
    }

    /* Walk the chain and free the certs */
    if (cert_and_key->cert_chain) {
        struct s2n_cert *node = cert_and_key->cert_chain->head;
        while (node) {
            /* Free the cert */
            POSIX_GUARD(s2n_free(&node->raw));
            /* update head so it won't point to freed memory */
            cert_and_key->cert_chain->head = node->next;
            /* Free the node */
            POSIX_GUARD(s2n_free_object((uint8_t **)&node, sizeof(struct s2n_cert)));
            node = cert_and_key->cert_chain->head;
        }

        POSIX_GUARD(s2n_free_object((uint8_t **)&cert_and_key->cert_chain, sizeof(struct s2n_cert_chain)));
    }

    if (cert_and_key->private_key) {
        POSIX_GUARD(s2n_pkey_free(cert_and_key->private_key));
        POSIX_GUARD(s2n_free_object((uint8_t **)&cert_and_key->private_key, sizeof(s2n_cert_private_key)));
    }

    uint32_t len = 0;

    if (cert_and_key->san_names) {
        POSIX_GUARD_RESULT(s2n_array_num_elements(cert_and_key->san_names, &len));
        for (uint32_t i = 0; i < len; i++) {
            struct s2n_blob *san_name = NULL;
            POSIX_GUARD_RESULT(s2n_array_get(cert_and_key->san_names, i, (void **)&san_name));
            POSIX_GUARD(s2n_free(san_name));
        }
        POSIX_GUARD_RESULT(s2n_array_free(cert_and_key->san_names));
        cert_and_key->san_names = NULL;
    }

    if (cert_and_key->cn_names) {
        POSIX_GUARD_RESULT(s2n_array_num_elements(cert_and_key->cn_names, &len));
        for (uint32_t i = 0; i < len; i++) {
            struct s2n_blob *cn_name = NULL;
            POSIX_GUARD_RESULT(s2n_array_get(cert_and_key->cn_names, i, (void **)&cn_name));
            POSIX_GUARD(s2n_free(cn_name));
        }
        POSIX_GUARD_RESULT(s2n_array_free(cert_and_key->cn_names));
        cert_and_key->cn_names = NULL;
    }

    POSIX_GUARD(s2n_free(&cert_and_key->ocsp_status));
    POSIX_GUARD(s2n_free(&cert_and_key->sct_list));

    POSIX_GUARD(s2n_free_object((uint8_t **)&cert_and_key, sizeof(struct s2n_cert_chain_and_key)));
    return 0;
}

int s2n_cert_chain_free(struct s2n_cert_chain *cert_chain)
{
    /* Walk the chain and free the certs/nodes allocated prior to failure */
    if (cert_chain) {
        struct s2n_cert *node = cert_chain->head;
        while (node) {
            /* Free the cert */
            POSIX_GUARD(s2n_free(&node->raw));
            /* update head so it won't point to freed memory */
            cert_chain->head = node->next;
            /* Free the node */
            POSIX_GUARD(s2n_free_object((uint8_t **)&node, sizeof(struct s2n_cert)));
            node = cert_chain->head;
        }
    }

    return S2N_SUCCESS;
}

int s2n_send_cert_chain(struct s2n_connection *conn, struct s2n_stuffer *out, struct s2n_cert_chain_and_key *chain_and_key)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(chain_and_key);
    struct s2n_cert_chain *chain = chain_and_key->cert_chain;
    POSIX_ENSURE_REF(chain);
    struct s2n_cert *cur_cert = chain->head;
    POSIX_ENSURE_REF(cur_cert);

    struct s2n_stuffer_reservation cert_chain_size = {0};
    POSIX_GUARD(s2n_stuffer_reserve_uint24(out, &cert_chain_size));

    /* Send certs and extensions (in TLS 1.3) */
    bool first_entry = true;
    while (cur_cert) {
        POSIX_ENSURE_REF(cur_cert);
        POSIX_GUARD(s2n_stuffer_write_uint24(out, cur_cert->raw.size));
        POSIX_GUARD(s2n_stuffer_write_bytes(out, cur_cert->raw.data, cur_cert->raw.size));

        /* According to https://tools.ietf.org/html/rfc8446#section-4.4.2,
         * If an extension applies to the entire chain, it SHOULD be included in
         * the first CertificateEntry.
         * While the spec allow extensions to be included in other certificate
         * entries, only the first matter to use here */
        if (conn->actual_protocol_version >= S2N_TLS13) {
            if (first_entry) {
                POSIX_GUARD(s2n_extension_list_send(S2N_EXTENSION_LIST_CERTIFICATE, conn, out));
                first_entry = false;
            } else {
                POSIX_GUARD(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, conn, out));
            }
        }
        cur_cert = cur_cert->next;
    }

    POSIX_GUARD(s2n_stuffer_write_vector_size(&cert_chain_size));

    return 0;
}

int s2n_send_empty_cert_chain(struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(out);
    POSIX_GUARD(s2n_stuffer_write_uint24(out, 0));
    return 0;
}

static int s2n_does_cert_san_match_hostname(const struct s2n_cert_chain_and_key *chain_and_key, const struct s2n_blob *dns_name)
{
    POSIX_ENSURE_REF(chain_and_key);
    POSIX_ENSURE_REF(dns_name);

    struct s2n_array *san_names = chain_and_key->san_names;
    uint32_t len = 0;
    POSIX_GUARD_RESULT(s2n_array_num_elements(san_names, &len));
    for (uint32_t i = 0; i < len; i++) {
        struct s2n_blob *san_name = NULL;
        POSIX_GUARD_RESULT(s2n_array_get(san_names, i, (void **)&san_name));
        POSIX_ENSURE_REF(san_name);
        if ((dns_name->size == san_name->size) && (strncasecmp((const char *) dns_name->data, (const char *) san_name->data, dns_name->size) == 0)) {
            return 1;
        }
    }

    return 0;
}

static int s2n_does_cert_cn_match_hostname(const struct s2n_cert_chain_and_key *chain_and_key, const struct s2n_blob *dns_name)
{
    POSIX_ENSURE_REF(chain_and_key);
    POSIX_ENSURE_REF(dns_name);

    struct s2n_array *cn_names = chain_and_key->cn_names;
    uint32_t len = 0;
    POSIX_GUARD_RESULT(s2n_array_num_elements(cn_names, &len));
    for (uint32_t i = 0; i < len; i++) {
        struct s2n_blob *cn_name = NULL;
        POSIX_GUARD_RESULT(s2n_array_get(cn_names, i, (void **)&cn_name));
        POSIX_ENSURE_REF(cn_name);
        if ((dns_name->size == cn_name->size) && (strncasecmp((const char *) dns_name->data, (const char *) cn_name->data, dns_name->size) == 0)) {
            return 1;
        }
    }

    return 0;
}

int s2n_cert_chain_and_key_matches_dns_name(const struct s2n_cert_chain_and_key *chain_and_key, const struct s2n_blob *dns_name)
{
    uint32_t len = 0;
    POSIX_GUARD_RESULT(s2n_array_num_elements(chain_and_key->san_names, &len));
    if (len > 0) {
        if (s2n_does_cert_san_match_hostname(chain_and_key, dns_name)) {
            return 1;
        }
    } else {
        /* Per https://tools.ietf.org/html/rfc6125#section-6.4.4 we only will
         * consider the CN for matching if no valid DNS entries are provided
         * in a SAN.
         */
        if (s2n_does_cert_cn_match_hostname(chain_and_key, dns_name)) {
            return 1;
        }
    }

    return 0;
}

int s2n_cert_chain_and_key_set_ctx(struct s2n_cert_chain_and_key *cert_and_key, void *ctx)
{
    cert_and_key->context = ctx;
    return 0;
}

void *s2n_cert_chain_and_key_get_ctx(struct s2n_cert_chain_and_key *cert_and_key)
{
    return cert_and_key->context;
}

s2n_pkey_type s2n_cert_chain_and_key_get_pkey_type(struct s2n_cert_chain_and_key *chain_and_key)
{
    return chain_and_key->cert_chain->head->pkey_type;
}

s2n_cert_private_key *s2n_cert_chain_and_key_get_private_key(struct s2n_cert_chain_and_key *chain_and_key)
{
    PTR_ENSURE_REF(chain_and_key);
    return chain_and_key->private_key;
}

int s2n_get_cert_chain_length(const struct s2n_cert_chain_and_key *chain_and_key, uint32_t *cert_length)
{
    POSIX_ENSURE_REF(chain_and_key);
    POSIX_ENSURE_REF(cert_length);

    struct s2n_cert *head_cert = chain_and_key->cert_chain->head;
    POSIX_ENSURE_REF(head_cert);
    *cert_length = 1;
    struct s2n_cert *next_cert = head_cert->next;
    while (next_cert != NULL) {
        *cert_length += 1;
        next_cert = next_cert->next;
    }

    return S2N_SUCCESS;
}

int s2n_get_cert_from_cert_chain(const struct s2n_cert_chain_and_key *chain_and_key, struct s2n_cert **out_cert,
                                 const uint32_t cert_idx)
{
    POSIX_ENSURE_REF(chain_and_key);
    POSIX_ENSURE_REF(out_cert);

    struct s2n_cert *cur_cert = chain_and_key->cert_chain->head;
    POSIX_ENSURE_REF(cur_cert);
    uint32_t counter = 0;

    struct s2n_cert *next_cert = cur_cert->next;

    while ((next_cert != NULL) && (counter < cert_idx)) {
        cur_cert  = next_cert;
        next_cert = next_cert->next;
        counter++;
    }

    POSIX_ENSURE(counter == cert_idx, S2N_ERR_NO_CERT_FOUND);
    POSIX_ENSURE(cur_cert != NULL, S2N_ERR_NO_CERT_FOUND);
    *out_cert = cur_cert;

    return S2N_SUCCESS;
}

int s2n_get_cert_der(const struct s2n_cert *cert, const uint8_t **out_cert_der, uint32_t *cert_length)
{
    POSIX_ENSURE_REF(cert);
    POSIX_ENSURE_REF(out_cert_der);
    POSIX_ENSURE_REF(cert_length);

    *cert_length = cert->raw.size;
    *out_cert_der = cert->raw.data;

    return S2N_SUCCESS;
}
