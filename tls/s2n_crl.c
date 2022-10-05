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
#include "tls/s2n_connection.h"

struct s2n_crl *s2n_crl_new(void) {
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    PTR_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_crl)));
    PTR_GUARD_POSIX(s2n_blob_zero(&mem));

    struct s2n_crl *crl = (struct s2n_crl *)(void*) mem.data;

    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return crl;
}

int s2n_crl_load_pem(struct s2n_crl *crl, uint8_t *pem, size_t len) {
    POSIX_ENSURE_REF(crl);
    POSIX_ENSURE(crl->crl == NULL, S2N_ERR_INVALID_ARGUMENT);

    struct s2n_blob pem_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&pem_blob, pem, len));

    struct s2n_stuffer pem_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&pem_stuffer, &pem_blob));
    POSIX_GUARD(s2n_stuffer_skip_write(&pem_stuffer, pem_blob.size));

    DEFER_CLEANUP(struct s2n_stuffer der_out_stuffer = {0}, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_growable_alloc(&der_out_stuffer, 2048));
    POSIX_GUARD(s2n_stuffer_crl_from_pem(&pem_stuffer, &der_out_stuffer));

    const uint8_t *data = der_out_stuffer.blob.data;
    crl->crl = d2i_X509_CRL(NULL, &data, der_out_stuffer.blob.size);
    POSIX_ENSURE(crl->crl != NULL, S2N_ERR_INVALID_PEM);

    return S2N_SUCCESS;
}

int s2n_crl_free(struct s2n_crl **crl) {
    if (crl == NULL) {
        return S2N_SUCCESS;
    }
    if (*crl == NULL) {
        return S2N_SUCCESS;
    }

    if ((*crl)->crl != NULL) {
        X509_CRL_free((*crl)->crl);
    }

    POSIX_GUARD(s2n_free_object((uint8_t **) crl, sizeof(struct s2n_crl)));

    *crl = NULL;

    return S2N_SUCCESS;
}

int s2n_crl_get_issuer_hash(struct s2n_crl *crl, unsigned long *hash) {
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
