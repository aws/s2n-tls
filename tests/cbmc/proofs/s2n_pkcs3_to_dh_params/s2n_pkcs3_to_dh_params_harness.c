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

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_dhe.h"

#include <assert.h>
#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/nondet.h>

/*
 * Since this function largely serves as a way to call specific OpenSSL
 * functions (which we do not fully emulate in CBMC), all we can assert
 * is memory safety. As such, several OpenSSL functions have been stubbed,
 * and a few functions have been left omitted since they do not affect
 * the proof.
 */
void s2n_pkcs3_to_dh_params_harness() {
    /* Non-deterministic inputs. */
    struct s2n_dh_params dh_params = {0};
    struct s2n_blob *pkcs3 = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(pkcs3));
    uint8_t *old_data = pkcs3->data;
    struct store_byte_from_buffer old_byte;
    save_byte_from_blob(pkcs3, &old_byte);
    __CPROVER_assume(s2n_blob_is_bounded(pkcs3, MAX_BLOB_SIZE));

    /* Non-deterministically set initialized (in s2n_mem) to true. */
    if(nondet_bool()) {
        s2n_mem_init();
    }

    /* Operation under verification. */
    if (s2n_pkcs3_to_dh_params(&dh_params, pkcs3) == S2N_SUCCESS) {
        assert(pkcs3->data == old_data);
        assert_byte_from_blob_matches(pkcs3, &old_byte);
    }
}
