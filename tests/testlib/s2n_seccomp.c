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

#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

#ifdef SECCOMP

    #include <seccomp.h>

DEFINE_POINTER_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);

extern bool s2n_use_color_in_output;

bool s2n_is_seccomp_supported()
{
    return true;
}

S2N_RESULT s2n_seccomp_init()
{
    /* Using SCMP_ACT_TRAP instead of SCMP_ACT_KILL makes this test easier
     * to debug. GDB will report exactly which syscalls triggered the signal.
     */
    DEFER_CLEANUP(scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP),
            seccomp_release_pointer);
    RESULT_ENSURE_REF(ctx);

    /* Basic requirements */
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0));
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0));

    /* Requirements for Ubuntu22 */
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0));

    /* See https://github.com/aws/aws-lc/blob/main/SANDBOXING.md#fork-protection */
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(madvise), 0));

    RESULT_GUARD_POSIX(seccomp_load(ctx));
    s2n_use_color_in_output = false;
    return S2N_RESULT_OK;
}

#else

bool s2n_is_seccomp_supported()
{
    return false;
}

S2N_RESULT s2n_seccomp_init()
{
    return S2N_RESULT_OK;
}

#endif
