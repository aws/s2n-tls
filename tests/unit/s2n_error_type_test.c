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

#include "s2n_test.h"

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "error/s2n_errno.h"

int main(void)
{
	BEGIN_TEST();

	s2n_errno = S2N_ERR_OK;
	EXPECT_EQUAL(S2N_ERR_T_OK, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_IO;
	EXPECT_EQUAL(S2N_ERR_T_IO, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_CLOSED;
	EXPECT_EQUAL(S2N_ERR_T_CLOSED, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_BLOCKED;
	EXPECT_EQUAL(S2N_ERR_T_BLOCKED, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_ALERT;
	EXPECT_EQUAL(S2N_ERR_T_ALERT, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_BAD_MESSAGE;
	EXPECT_EQUAL(S2N_ERR_T_PROTO, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_FSTAT;
	EXPECT_EQUAL(S2N_ERR_T_INTERNAL, s2n_error_get_type(s2n_errno));
	s2n_errno = S2N_ERR_INVALID_BASE64;
	EXPECT_EQUAL(S2N_ERR_T_USAGE, s2n_error_get_type(s2n_errno));

	END_TEST();
}
