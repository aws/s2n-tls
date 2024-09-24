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

/* "seccomp" allows the kernel to control what system calls an application
 * is allowed to make based on a provided filter.
 *
 * seccomp is commonly used for "sandboxing" programs for security reasons.
 */
S2N_RESULT s2n_seccomp_init()
{
    /* Using SCMP_ACT_TRAP instead of SCMP_ACT_KILL as the default action
     * makes this test easier to debug. GDB can be used to debug failures caused
     * by SCMP_ACT_TRAP, but not caused by SCMP_ACT_KILL.
     */
    DEFER_CLEANUP(scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP),
            seccomp_release_pointer);
    RESULT_ENSURE_REF(ctx);

    /* Basic requirements: s2n-tls is known to need these system calls in order
     * to operate. Adding a new system call to this list means that any application
     * using s2n-tls with seccomp will potentially also need to update its filter rules.
     *
     * Do not add any variation of "open" to this list. One of the primary reasons
     * that an application would choose to use seccomp is to prevent opening files,
     * similar to chroot.
     */
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

    /* Ubuntu22 uses "newfstatat" instead of "fstat" */
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0));

    /* See https://github.com/aws/aws-lc/blob/main/SANDBOXING.md#fork-protection:
     * We can just cause the madavise call to fail rather than blocking it entirely. */
    RESULT_GUARD_POSIX(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(madvise), 0));

    /* Checking whether the terminal supports color requires an additional
     * system call. Preemptively disable color.
     */
    s2n_use_color_in_output = false;

    RESULT_GUARD_POSIX(seccomp_load(ctx));
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
