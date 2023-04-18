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
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

#define TEST_ERRNO S2N_ERR_T_INTERNAL_END

#define SETUP_TEST(conn)                       \
    EXPECT_SUCCESS(s2n_connection_wipe(conn)); \
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

#define EXPECT_BLINDING(conn)                            \
    EXPECT_NOT_EQUAL(s2n_connection_get_delay(conn), 0); \
    EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));

#define EXPECT_NO_BLINDING(conn)                     \
    EXPECT_EQUAL(s2n_connection_get_delay(conn), 0); \
    EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

S2N_RESULT s2n_result_func(bool success)
{
    RESULT_ENSURE(success, TEST_ERRNO);
    return S2N_RESULT_OK;
}

int s2n_posix_func(bool success)
{
    POSIX_ENSURE(success, TEST_ERRNO);
    return S2N_SUCCESS;
}

int ptr_value = 0;
int *s2n_ptr_func(bool success)
{
    PTR_ENSURE(success, TEST_ERRNO);
    return &ptr_value;
}

S2N_RESULT s2n_result_test(struct s2n_connection *conn)
{
    WITH_ERROR_BLINDING(conn, RESULT_GUARD(s2n_result_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, RESULT_ENSURE(true, S2N_ERR_UNIMPLEMENTED));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, RESULT_GUARD_POSIX(s2n_posix_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, RESULT_GUARD_PTR(s2n_ptr_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, RESULT_GUARD(s2n_result_func(false)));
    return S2N_RESULT_OK;
}

int s2n_posix_test(struct s2n_connection *conn)
{
    WITH_ERROR_BLINDING(conn, POSIX_GUARD_RESULT(s2n_result_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, POSIX_ENSURE(true, S2N_ERR_UNIMPLEMENTED));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, POSIX_GUARD(s2n_posix_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, POSIX_GUARD_PTR(s2n_ptr_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, POSIX_GUARD(s2n_posix_func(false)));
    return S2N_SUCCESS;
}

int *s2n_ptr_test(struct s2n_connection *conn)
{
    WITH_ERROR_BLINDING(conn, PTR_GUARD_RESULT(s2n_result_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, PTR_ENSURE(true, S2N_ERR_UNIMPLEMENTED));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, PTR_GUARD_POSIX(s2n_posix_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, PTR_GUARD(s2n_ptr_func(true)));
    EXPECT_NO_BLINDING(conn);

    WITH_ERROR_BLINDING(conn, PTR_GUARD(s2n_ptr_func(false)));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_connection_apply_error_blinding */
    {
        /* Safety check */
        struct s2n_connection *conn = NULL;
        EXPECT_ERROR_WITH_ERRNO(s2n_connection_apply_error_blinding(NULL), S2N_ERR_NULL);
        EXPECT_OK(s2n_connection_apply_error_blinding(&conn));

        conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);

        /* No-op for no error */
        {
            SETUP_TEST(conn);
            s2n_errno = S2N_ERR_OK;
            EXPECT_OK(s2n_connection_apply_error_blinding(&conn));
            EXPECT_NO_BLINDING(conn);
        };

        /* No-op for retriable errors */
        {
            SETUP_TEST(conn);
            s2n_errno = S2N_ERR_IO_BLOCKED;
            EXPECT_OK(s2n_connection_apply_error_blinding(&conn));
            EXPECT_NO_BLINDING(conn);
        };

        /* Closes connection but does not blind for non-blinding errors */
        {
            SETUP_TEST(conn);
            s2n_errno = S2N_ERR_CIPHER_NOT_SUPPORTED;
            EXPECT_OK(s2n_connection_apply_error_blinding(&conn));
            EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
        };

        /* Blinds for an average error */
        {
            SETUP_TEST(conn);
            s2n_errno = S2N_ERR_UNIMPLEMENTED;
            EXPECT_OK(s2n_connection_apply_error_blinding(&conn));
            EXPECT_BLINDING(conn);
        };

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: WITH_ERROR_BLINDING macro
     * The WITH_ERROR_BLINDING macro relies on the current method exiting early.
     * We can't trigger that behavior in main, so we call separate test methods.
     * Each test method verifies that some success cases don't lead to blinding, then
     * triggers blinding. Back in main, we verify that the blinding occurred. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);

        SETUP_TEST(conn);
        EXPECT_ERROR_WITH_ERRNO(s2n_result_test(conn), TEST_ERRNO);
        EXPECT_BLINDING(conn);

        SETUP_TEST(conn);
        EXPECT_FAILURE_WITH_ERRNO(s2n_posix_test(conn), TEST_ERRNO);
        EXPECT_BLINDING(conn);

        SETUP_TEST(conn);
        EXPECT_NULL(s2n_ptr_test(conn));
        EXPECT_NOT_EQUAL(s2n_connection_get_delay(conn), 0);
        EXPECT_BLINDING(conn);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}
