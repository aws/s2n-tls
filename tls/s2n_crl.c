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

#include "s2n_crl.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_openssl_x509.h"
#include "utils/s2n_asn1_time.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_rfc5952.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"

static struct s2n_x509_crl* s2n_x509_crl_new(void) {
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    PTR_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_x509_crl)));

    struct s2n_x509_crl *crl = (struct s2n_x509_crl*)(void*) mem.data;
    crl->crl = NULL;

    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return crl;
}

int s2n_x509_crl_from_pem(uint8_t *pem, size_t len, struct s2n_x509_crl **crl) {
    POSIX_ENSURE_REF(crl);

    struct s2n_blob pem_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&pem_blob, pem, len));

    struct s2n_stuffer pem_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&pem_stuffer, &pem_blob));
    POSIX_GUARD(s2n_stuffer_skip_write(&pem_stuffer, pem_blob.size));

    DEFER_CLEANUP(struct s2n_stuffer der_out_stuffer = {0}, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_growable_alloc(&der_out_stuffer, 2048));
    POSIX_GUARD(s2n_stuffer_crl_from_pem(&pem_stuffer, &der_out_stuffer));

    DEFER_CLEANUP(struct s2n_blob crl_blob = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&crl_blob, s2n_stuffer_data_available(&der_out_stuffer)));
    POSIX_GUARD(s2n_stuffer_read(&der_out_stuffer, &crl_blob));

    *crl = s2n_x509_crl_new();
    POSIX_ENSURE_REF(*crl);

    const uint8_t *data = crl_blob.data;
    (*crl)->crl = d2i_X509_CRL(NULL, &data, crl_blob.size);
    POSIX_ENSURE((*crl)->crl != NULL, S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    return S2N_SUCCESS;
}

int s2n_x509_crl_free(struct s2n_x509_crl *crl) {
    if (crl == NULL) {
        return S2N_SUCCESS;
    }

    if (crl->crl) {
        X509_CRL_free(crl->crl);
    }
    POSIX_GUARD(s2n_free_object((uint8_t **) &crl, sizeof(struct s2n_x509_crl)));

    return S2N_SUCCESS;
}

int s2n_x509_crl_get_issuer_hash(struct s2n_x509_crl *crl, unsigned long *hash) {
    POSIX_ENSURE_REF(crl);
    POSIX_ENSURE_REF(crl->crl);
    POSIX_ENSURE_REF(hash);

    X509_NAME *crl_name = X509_CRL_get_issuer(crl->crl);
    POSIX_ENSURE_REF(crl_name);

    unsigned long temp_hash = X509_NAME_hash(crl_name);
    POSIX_ENSURE(temp_hash != 0, S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    *hash = temp_hash;

    return S2N_SUCCESS;
}
