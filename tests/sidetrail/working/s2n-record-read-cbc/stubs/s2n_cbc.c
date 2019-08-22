/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <smack.h>
#include "ct-verif.h"
#include "../sidetrail.h"

#define MAX_LEAKAGE_DIFFERENCE  68

int nondet();

int s2n_verify_cbc(struct s2n_connection *conn, struct s2n_hmac_state *hmac, struct s2n_blob *decrypted)
{
  int leakage = nondet();
  /* We have a proof that the max leakage this step can introduce is MAX_LEAKAGE_DIFFERENCE */
  __VERIFIER_assume(leakage >= 0);
  __VERIFIER_assume(leakage < MAX_LEAKAGE_DIFFERENCE);
  __VERIFIER_ASSUME_LEAKAGE(leakage);
  return 0;
}
