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

/* This captures Darwin specialities. This is the only APPLE flavor we care
 * about.
 */
#if defined(__APPLE__)
    typedef struct _opaque_pthread_once_t  __darwin_pthread_once_t;
    typedef __darwin_pthread_once_t pthread_once_t;
    #define _DARWIN_C_SOURCE
    #include <sys/mman.h>
    #if !defined(MAP_ANONYMOUS)
        #define MAP_ANONYMOUS MAP_ANON
    #endif
#else
    #if !defined(_GNU_SOURCE)
        #define _GNU_SOURCE
    #endif
    #include <sys/mman.h>
#endif

#include "error/s2n_errno.h"
#include "utils/s2n_fork_detection.h"
#include "utils/s2n_safety_macros.h"

#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


/* pthread should work on Darwin, but neither madvise or minherit provides the
 * required functionality in that kernel. Hence, restrict usage of madvise to
 * Linux and minherit to some BSD-flavored kernels. We do not consider Win.
 *
 * Android Trusty defines __linux__ for some reason, protect against that.
 */
#if defined(__linux__) && !defined(__TRUSTY__)
#define USE_MADVISE
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
#define USE_MINHERIT
#endif

#if defined(USE_MINHERIT) && defined(USE_MADVISE)
#error "Both USE_MINHERIT and USE_MADVISE are defined. This should not be possible."
#endif

#if defined(USE_MADVISE) && defined(MADV_WIPEONFORK)
S2N_STATIC_ASSERT(MADV_WIPEONFORK == 18, MADV_WIPEONFORK_is_defined_but_is_not_equal_to_18)
#else
#define MADV_WIPEONFORK 18
#endif

/* These variables are used to disable all fork detection mechanisms or at the
 * individual level during testing.
 */
#define S2N_FORK_DETECT_IGNORE 0
#define S2N_FORK_DETECT_DO_NOT_IGNORE 1
static int ignore_wipeonfork_or_inherit_zero_method_for_testing = S2N_FORK_DETECT_DO_NOT_IGNORE;
static int ignore_pthread_atfork_method_for_testing = S2N_FORK_DETECT_DO_NOT_IGNORE;
static int ignore_fork_detection_for_testing = S2N_FORK_DETECT_DO_NOT_IGNORE;

#define FORK_EVENT 0
#define NO_FORK_EVENT 1

struct FGN_STATE {
    /* The current cached fork generation number for this process */
    uint64_t current_fork_generation_number;

    /* Semaphore controlling access to the shared sentinel and signaling whether
     * fork detection is enabled or not. We could use zero_on_fork_addr, but
     * avoid overloading by using an explicit variable.
     */
    int is_fork_detection_enabled;

    /* Sentinel that signals a fork event has occurred */
    volatile char *zero_on_fork_addr;

    pthread_once_t fork_detection_once;
    pthread_rwlock_t fork_detection_rw_lock;
};

/* We only need a single statically initialised state. Note, the state is
 * inherited by child processes.
 */
static struct FGN_STATE fgn_state = {
    .current_fork_generation_number = 0,
    .is_fork_detection_enabled = S2N_FAILURE,
    .zero_on_fork_addr = NULL,
    .fork_detection_once = PTHREAD_ONCE_INIT,
    .fork_detection_rw_lock = PTHREAD_RWLOCK_INITIALIZER,
};


/* Can currently never fail. See initialise_fork_detection_methods() for
 * motivation.
 */
static inline void initialise_wipeonfork_best_effort(void *addr, long page_size)
{
#if defined(USE_MADVISE)
    /* Make sure that madvise() rejects invalid memory advice arguments.
     * Some versions of qemu (up to at least 5.0.0-rc4, see
     * linux-user/syscall.c) ignore madvise calls and just return zero (i.e.
     * success). Therefore try an invalid call to check that the implementation
     * of madvise is actually rejecting unknown "advice" values.
     *
     * This is not regarded as an error, but an inability to determine whether
     * MADV_WIPEFORK is supported or not. We fall back to pthread_atfork if not.
     */
    if (madvise(addr, (size_t) page_size, -1) != 0) {
        /* Ignored on purpose. Best-effort initialisation. */
        madvise(addr, (size_t) page_size, MADV_WIPEONFORK);
    }
#endif
}

static inline int initialise_inherit_zero(void *addr, long page_size)
{
#if defined(USE_MINHERIT) && defined(MAP_INHERIT_ZERO)
    POSIX_ENSURE(minherit(addr, pagesize, MAP_INHERIT_ZERO) == 0, S2N_ERR_FORK_DETECTION_INIT);
#endif

    return S2N_SUCCESS;
}

static void pthread_atfork_on_fork(void)
{
  /* This zeroises the first byte of the memory page pointed to by
   * *zero_on_fork_addr. This is the same byte used as fork event detection
   * sentinel in s2n_get_fork_generation_number(). The same memory page, and in
   * turn, the byte, is also the memory zeroised by the MADV_WIPEONFORK fork
   * detection mechanism.
   *
   * Aquire locks to be on the safe side. We want to avoid the checks in
   * s2n_get_fork_generation_number() getting executed before setting the sentinel
   * flag. The write lock prevents any other thread from owning any other type
   * of lock.
   *
   * pthread_atfork_on_fork() cannot return errors. Hence, there is no way to
   * gracefully recover if [un]locking fails.
   */
  if (pthread_rwlock_wrlock(&fgn_state.fork_detection_rw_lock) != 0) {
    abort();
  }
  *fgn_state.zero_on_fork_addr = 0;
  if (pthread_rwlock_unlock(&fgn_state.fork_detection_rw_lock) != 0) {
    abort();
  }
}

static int inititalise_pthread_atfork(void)
{
  /* Register the fork handler pthread_atfork_on_fork that is excuted in the
   * child process after a fork.
   */
  POSIX_ENSURE(pthread_atfork(NULL, NULL, pthread_atfork_on_fork) == 0, S2N_ERR_FORK_DETECTION_INIT);

  return S2N_SUCCESS;
}

static void initialise_fork_detection_methods(void)
{
    void *addr = MAP_FAILED;
    long page_size = 0;

    /* Only used to disable fork detection mechanisms during testing. */
    if (ignore_wipeonfork_or_inherit_zero_method_for_testing == S2N_FORK_DETECT_IGNORE &&
        ignore_pthread_atfork_method_for_testing == S2N_FORK_DETECT_IGNORE) {

        ignore_fork_detection_for_testing = S2N_FORK_DETECT_IGNORE;
        goto end;
    }

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        goto end;
    }

    addr = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        goto end;
    }

    /* Some system don't define MADV_WIPEONFORK in sys/mman.h but the kernel
     * still supports the mechanism (AL2 being a prime example). Likely because
     * glibc on the system is old. We might be able to include kernel header
     * files directly, that define MADV_WIPEONFORK, conditioning on specific
     * OS's. But it is a mess. A more reliable method is to probe the system, at
     * run-time, whether madvise supports the MADV_WIPEONFORK advice. However,
     * the method to probe for this feature is equivalent to actually attempting
     * to initialise the MADV_WIPEONFORK fork detection. Compare with
     * probe_madv_wipeonfork_support() (used for testing).
     *
     * Instead, we apply best-effort to initialise the MADV_WIPEONFORK fork
     * detection and otherwise always require pthread_atfork to be initialised.
     * We also currently always apply prediction resistance. So, this should be
     * a safe default.
     */
    if (ignore_wipeonfork_or_inherit_zero_method_for_testing == S2N_FORK_DETECT_DO_NOT_IGNORE) {
        initialise_wipeonfork_best_effort(addr, page_size);
    }

    if (ignore_wipeonfork_or_inherit_zero_method_for_testing == S2N_FORK_DETECT_DO_NOT_IGNORE &&
        initialise_inherit_zero(addr, page_size) != S2N_SUCCESS) {
        goto end;
    }

    if (ignore_pthread_atfork_method_for_testing == S2N_FORK_DETECT_DO_NOT_IGNORE &&
        inititalise_pthread_atfork() != S2N_SUCCESS) {
        goto end;
    }

    fgn_state.zero_on_fork_addr = addr;
    *fgn_state.zero_on_fork_addr = NO_FORK_EVENT;
    fgn_state.is_fork_detection_enabled = S2N_SUCCESS;

end:
    if (fgn_state.is_fork_detection_enabled == S2N_FAILURE && addr != MAP_FAILED) {
        munmap(addr, (size_t) page_size);
        addr = NULL;
        fgn_state.zero_on_fork_addr = NULL;
    }
}

/* Returns the current fork generation number in return_fork_generation_number.
 * Caller must synchronise access to return_fork_generation_number.
 */
int s2n_get_fork_generation_number(uint64_t *return_fork_generation_number)
{
    POSIX_ENSURE(pthread_once(&fgn_state.fork_detection_once, initialise_fork_detection_methods) == 0, S2N_ERR_FORK_DETECTION_INIT);

    if (ignore_fork_detection_for_testing == S2N_FORK_DETECT_IGNORE) {
        /* Fork detection is meant to be disabled. Hence, return success. */
        return S2N_SUCCESS;
    }

    POSIX_ENSURE(fgn_state.is_fork_detection_enabled == S2N_SUCCESS, S2N_ERR_FORK_DETECTION_INIT);

    /* In most cases, we would not need to increment the fork generation number.
     * So, it is cheaper, in the expected case, to take an optimistic read lock
     * and later aquire a write lock if needed.
     * Note that we set the returned fgn before checking for a fork event. We
     * need to do this because thread execution might change between releasing
     * the read lock and taking the write lock. In that time span, another
     * thread can reset the fork event detection sentinel and we return from
     * s2n_get_fork_generation_number() without setting the returned fgn
     * appropriately.
     */
    POSIX_ENSURE(pthread_rwlock_rdlock(&fgn_state.fork_detection_rw_lock) == 0, S2N_ERR_RETRIEVE_FORK_GENERATION_NUMBER);
    *return_fork_generation_number = fgn_state.current_fork_generation_number;
    if (*fgn_state.zero_on_fork_addr != FORK_EVENT) {
        POSIX_ENSURE(pthread_rwlock_unlock(&fgn_state.fork_detection_rw_lock) == 0, S2N_ERR_RETRIEVE_FORK_GENERATION_NUMBER);
        return S2N_SUCCESS;
    }
    POSIX_ENSURE(pthread_rwlock_unlock(&fgn_state.fork_detection_rw_lock) == 0, S2N_ERR_RETRIEVE_FORK_GENERATION_NUMBER);

    /* We are mutating the process-global, cached fork generation number. Need to
     * acquire the write lock for that. Set returned fgn before checking the if
     * condition with the same reasons as above.
     */
    POSIX_ENSURE(pthread_rwlock_wrlock(&fgn_state.fork_detection_rw_lock) == 0, S2N_ERR_RETRIEVE_FORK_GENERATION_NUMBER);
    *return_fork_generation_number = fgn_state.current_fork_generation_number;
    if (*fgn_state.zero_on_fork_addr == FORK_EVENT) {
        /* Fork has been detected; reset sentinel, increment cached fork
         * generation nunber (which is now "current" in this child process), and
         * write incremented fork generation number to the output parameter.
         */
        *fgn_state.zero_on_fork_addr = NO_FORK_EVENT;
        fgn_state.current_fork_generation_number = fgn_state.current_fork_generation_number + 1;
        *return_fork_generation_number = fgn_state.current_fork_generation_number;
    }
    POSIX_ENSURE(pthread_rwlock_unlock(&fgn_state.fork_detection_rw_lock) == 0, S2N_ERR_RETRIEVE_FORK_GENERATION_NUMBER);

    return S2N_SUCCESS;
}

#if defined(USE_MADVISE)
/* Run-time probe checking whether the system supports the MADV_WIPEONFORK fork
 * detection mechanism.
 *
 * Return value:
 *  If not supported, returns S2N_FAILURE.
 *  If supported, returns S2N_SUCCESS.
 */
static int probe_madv_wipeonfork_support(void) {

    void *probe_addr = MAP_FAILED;
    long page_size = 0;
    int result = S2N_FAILURE;

    page_size = sysconf(_SC_PAGESIZE);
    POSIX_ENSURE(page_size > 0, S2N_ERR_FORK_DETECTION_INIT);

    probe_addr = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    POSIX_ENSURE(probe_addr != MAP_FAILED, S2N_ERR_FORK_DETECTION_INIT);


    if (madvise(probe_addr, (size_t) page_size, -1) != 0 &&
        madvise(probe_addr, (size_t) page_size, MADV_WIPEONFORK) == 0) {
        result = S2N_SUCCESS;
    }

    munmap(probe_addr, (size_t) page_size);

    return result;
}
#endif

int assert_madv_wipeonfork_is_supported(void)
{
    int result = S2N_FAILURE;
#if defined(USE_MADVISE)
    result = probe_madv_wipeonfork_support();
#endif
    return result;
}

int assert_map_inherit_zero_is_supported(void)
{
    int result = S2N_FAILURE;
#if defined(USE_MINHERIT) && defined(MAP_INHERIT_ZERO)
    result = S2N_SUCCESS;
#else
    return result;
#endif
}

/* Use for testing only */
void FOR_TESTING_ignore_wipeonfork_and_inherit_zero(void) {
    ignore_wipeonfork_or_inherit_zero_method_for_testing = S2N_FORK_DETECT_IGNORE;
}

void FOR_TESTING_ignore_pthread_atfork(void) {
    ignore_pthread_atfork_method_for_testing = S2N_FORK_DETECT_IGNORE;
}

