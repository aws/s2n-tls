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

#include "crypto/s2n_pkey_mldsa.h"

#include "crypto/s2n_pkey_evp.h"
#include "utils/s2n_safety.h"

bool s2n_pkey_mldsa_supported()
{
#if S2N_LIBCRYPTO_SUPPORTS_MLDSA
    return true;
#else
    return false;
#endif
}

int s2n_pkey_mldsa_sign(const struct s2n_pkey *priv_key, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_UNIMPLEMENTED);
    return S2N_SUCCESS;
}

int s2n_pkey_mldsa_verify(const struct s2n_pkey *pub_key, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_UNIMPLEMENTED);
    return S2N_SUCCESS;
}

S2N_RESULT s2n_pkey_mldsa_init(struct s2n_pkey *pkey)
{
    RESULT_ENSURE_REF(pkey);
    RESULT_GUARD(s2n_pkey_evp_init(pkey));
    pkey->sign = &s2n_pkey_mldsa_sign;
    pkey->verify = &s2n_pkey_mldsa_verify;
    return S2N_RESULT_OK;
}
