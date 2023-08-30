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

#include "crypto/s2n_openssl_x509.h"

#include "api/s2n.h"

#define S2N_MAX_ALLOWED_CERT_TRAILING_BYTES 3

S2N_CLEANUP_RESULT s2n_openssl_x509_stack_pop_free(STACK_OF(X509) **cert_chain)
{
    RESULT_ENSURE_REF(*cert_chain);
    sk_X509_pop_free(*cert_chain, X509_free);
    *cert_chain = NULL;
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_openssl_asn1_time_free_pointer(ASN1_GENERALIZEDTIME **time_ptr)
{
    /* The ANS1_*TIME structs are just typedef wrappers around ASN1_STRING
     *
     * The ASN1_TIME, ASN1_UTCTIME and ASN1_GENERALIZEDTIME structures are
     * represented as an ASN1_STRING internally and can be freed up using
     * ASN1_STRING_free().
     * https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_to_tm.html
     */
    RESULT_ENSURE_REF(*time_ptr);
    ASN1_STRING_free((ASN1_STRING *) *time_ptr);
    *time_ptr = NULL;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_openssl_x509_parse(struct s2n_blob *cert_asn1_der, X509 **cert, uint32_t *cert_len)
{
    RESULT_ENSURE_REF(cert_asn1_der);
    RESULT_ENSURE_REF(cert);
    RESULT_ENSURE_REF(cert_len);

    const uint8_t *cert_data_ptr = cert_asn1_der->data;

    *cert = d2i_X509(NULL, (const unsigned char **) &cert_data_ptr, cert_asn1_der->size);
    RESULT_ENSURE(*cert, S2N_ERR_CERT_INVALID);

    /* If cert parsing is successful, d2i_X509 increments *cert_data_ptr to the byte following the
     * parsed data.
     */
    *cert_len = cert_data_ptr - cert_asn1_der->data;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_openssl_x509_validate_length(struct s2n_blob *cert_asn1_der, uint32_t cert_len)
{
    RESULT_ENSURE_REF(cert_asn1_der);

    RESULT_ENSURE_GTE(cert_asn1_der->size, cert_len);

    /* Some asn1-encoded certificates contain extraneous trailing bytes. s2n-tls permits some
     * number of trailing bytes for compatibility with these certificates.
     */
    uint32_t trailing_bytes = cert_asn1_der->size - cert_len;
    RESULT_ENSURE(trailing_bytes <= S2N_MAX_ALLOWED_CERT_TRAILING_BYTES, S2N_ERR_DECODE_CERTIFICATE);

    return S2N_RESULT_OK;
}
