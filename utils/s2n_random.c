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

/*
 * _XOPEN_SOURCE is needed for resolving the constant O_CLOEXEC in some
 * environments. We use _XOPEN_SOURCE instead of _GNU_SOURCE because
 * _GNU_SOURCE is not portable and breaks when attempting to build rust
 * bindings on MacOS.
 *
 * https://man7.org/linux/man-pages/man2/open.2.html
 * The O_CLOEXEC, O_DIRECTORY, and O_NOFOLLOW flags are not
 * specified in POSIX.1-2001, but are specified in POSIX.1-2008.
 * Since glibc 2.12, one can obtain their definitions by defining
 * either _POSIX_C_SOURCE with a value greater than or equal to
 * 200809L or _XOPEN_SOURCE with a value greater than or equal to
 * 700.  In glibc 2.11 and earlier, one obtains the definitions by
 * defining _GNU_SOURCE.
 *
 * We use two feature probes to detect the need to perform this workaround.
 * It is only applied if we can't get CLOEXEC without it and the build doesn't
 * fail with _XOPEN_SOURCE being defined.
 *
 * # Relevent Links
 *
 * - POSIX.1-2017: https://pubs.opengroup.org/onlinepubs/9699919799
 * - https://stackoverflow.com/a/5724485
 * - https://stackoverflow.com/a/5583764
 */
#if !defined(S2N_CLOEXEC_SUPPORTED) && defined(S2N_CLOEXEC_XOPEN_SUPPORTED) && !defined(_XOPEN_SOURCE)
    #define _XOPEN_SOURCE 700
    #include <fcntl.h>
    #undef _XOPEN_SOURCE
#else
    #include <fcntl.h>
#endif
#include <errno.h>
#include <limits.h>
/* LibreSSL requires <openssl/rand.h> include.
 * https://github.com/aws/s2n-tls/issues/153#issuecomment-129651643
 */
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_libcrypto.h"
#include "error/s2n_errno.h"
#include "s2n_io.h"
#include "utils/s2n_init.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

#if defined(O_CLOEXEC)
    #define ENTROPY_FLAGS O_RDONLY | O_CLOEXEC
#else
    #define ENTROPY_FLAGS O_RDONLY
#endif

/* One second in nanoseconds */
#define ONE_S INT64_C(1000000000)

/* Placeholder value for an uninitialized entropy file descriptor */
#define UNINITIALIZED_ENTROPY_FD -1

static struct s2n_rand_device s2n_dev_urandom = {
    .source = "/dev/urandom",
    .fd = UNINITIALIZED_ENTROPY_FD,
};

static int s2n_rand_init_cb_impl(void);
static int s2n_rand_cleanup_cb_impl(void);
static int s2n_rand_get_entropy_from_urandom(void *ptr, uint32_t size);

static int s2n_rand_entropy_fd_close_ptr(int *fd)
{
    if (fd && *fd != UNINITIALIZED_ENTROPY_FD) {
        close(*fd);
    }
    return S2N_SUCCESS;
}

/*
 * Delegate randomness to libcrypto when:
 *  - We are in FIPS mode, or
 *  - Libcrypto provides distinct public/private random streams.
 */
bool s2n_use_libcrypto_rand(void)
{
    if (s2n_is_in_fips_mode()) {
        return true;
    }

    if (s2n_libcrypto_is_awslc()) {
#if S2N_LIBCRYPTO_SUPPORTS_PUBLIC_RAND
        /* AWS-LC with RAND_public_bytes: distinct streams */
        return true;
#else
        /* AWS-LC without public rand: no distinct streams */
        return false;
#endif
    } else {
#if S2N_LIBCRYPTO_SUPPORTS_PRIVATE_RAND
        /* Non-AWS-LC: RAND_priv_bytes implies distinct stream */
        return true;
#endif
    }

    return false;
}

static S2N_RESULT s2n_get_libcrypto_private_random_data(struct s2n_blob *out_blob)
{
    RESULT_GUARD_PTR(out_blob);
    RESULT_ENSURE_REF(out_blob->data);
#if S2N_LIBCRYPTO_SUPPORTS_PRIVATE_RAND
    RESULT_GUARD_OSSL(RAND_priv_bytes(out_blob->data, out_blob->size), S2N_ERR_DRBG);
#else
    RESULT_GUARD_OSSL(RAND_bytes(out_blob->data, out_blob->size), S2N_ERR_DRBG);
#endif
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_libcrypto_public_random_data(struct s2n_blob *out_blob)
{
    RESULT_GUARD_PTR(out_blob);
    RESULT_ENSURE_REF(out_blob->data);
#if S2N_LIBCRYPTO_SUPPORTS_PUBLIC_RAND
    RESULT_GUARD_OSSL(RAND_public_bytes(out_blob->data, out_blob->size), S2N_ERR_DRBG);
#else
    RESULT_GUARD_OSSL(RAND_bytes(out_blob->data, out_blob->size), S2N_ERR_DRBG);
#endif
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_system_random_data(struct s2n_blob *blob)
{
    RESULT_GUARD_PTR(blob);
    RESULT_GUARD_PTR(blob->data);

    /* This function sets s2n_errno on failure */
    RESULT_GUARD_POSIX(s2n_rand_get_entropy_from_urandom(blob->data, blob->size));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_public_random_data(struct s2n_blob *blob)
{
    if (s2n_use_libcrypto_rand()) {
        RESULT_GUARD(s2n_get_libcrypto_public_random_data(blob));
    } else {
        RESULT_GUARD(s2n_get_system_random_data(blob));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_private_random_data(struct s2n_blob *blob)
{
    if (s2n_use_libcrypto_rand()) {
        RESULT_GUARD(s2n_get_libcrypto_private_random_data(blob));
    } else {
        RESULT_GUARD(s2n_get_system_random_data(blob));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rand_get_urandom_for_test(struct s2n_rand_device **device)
{
    RESULT_ENSURE_REF(device);
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    *device = &s2n_dev_urandom;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_rand_device_open(struct s2n_rand_device *device)
{
    RESULT_ENSURE_REF(device);
    RESULT_ENSURE_REF(device->source);

    DEFER_CLEANUP(int fd = -1, s2n_rand_entropy_fd_close_ptr);
    S2N_IO_RETRY_EINTR(fd, open(device->source, ENTROPY_FLAGS));
    RESULT_ENSURE(fd >= 0, S2N_ERR_OPEN_RANDOM);

    struct stat st = { 0 };
    RESULT_ENSURE(fstat(fd, &st) == 0, S2N_ERR_OPEN_RANDOM);
    device->dev = st.st_dev;
    device->ino = st.st_ino;
    device->mode = st.st_mode;
    device->rdev = st.st_rdev;

    device->fd = fd;

    /* Disable closing the file descriptor with defer cleanup */
    fd = UNINITIALIZED_ENTROPY_FD;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rand_device_validate(struct s2n_rand_device *device)
{
    RESULT_ENSURE_REF(device);
    RESULT_ENSURE_NE(device->fd, UNINITIALIZED_ENTROPY_FD);

    struct stat st = { 0 };
    RESULT_ENSURE(fstat(device->fd, &st) == 0, S2N_ERR_OPEN_RANDOM);
    RESULT_ENSURE_EQ(device->dev, st.st_dev);
    RESULT_ENSURE_EQ(device->ino, st.st_ino);
    RESULT_ENSURE_EQ(device->rdev, st.st_rdev);

    mode_t permission_mask = ~(S_IRWXU | S_IRWXG | S_IRWXO);
    RESULT_ENSURE_EQ((device->mode ^ st.st_mode) & permission_mask, 0);

    return S2N_RESULT_OK;
}

static int s2n_rand_get_entropy_from_urandom(void *ptr, uint32_t size)
{
    POSIX_ENSURE_REF(ptr);
    POSIX_ENSURE(s2n_dev_urandom.fd != UNINITIALIZED_ENTROPY_FD, S2N_ERR_NOT_INITIALIZED);

    if (s2n_result_is_error(s2n_rand_device_validate(&s2n_dev_urandom))) {
        POSIX_GUARD_RESULT(s2n_rand_device_open(&s2n_dev_urandom));
    }

    uint8_t *data = ptr;
    uint32_t n = size;
    struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = 0 };
    long backoff = 1;

    while (n) {
        errno = 0;
        int r = read(s2n_dev_urandom.fd, data, n);
        if (r <= 0) {
            if (errno != EINTR) {
                backoff = MIN(backoff * 10, ONE_S - 1);
                sleep_time.tv_nsec = backoff;
                do {
                    r = nanosleep(&sleep_time, &sleep_time);
                } while (r != 0);
            }

            continue;
        }

        data += r;
        n -= r;
    }

    return S2N_SUCCESS;
}

/*
 * Return a random number in the range [0, bound)
 */
S2N_RESULT s2n_public_random(int64_t bound, uint64_t *output)
{
    uint64_t r = 0;

    RESULT_ENSURE_GT(bound, 0);

    while (1) {
        struct s2n_blob blob = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&blob, (void *) &r, sizeof(r)));
        RESULT_GUARD(s2n_get_public_random_data(&blob));

        if (r < (UINT64_MAX - (UINT64_MAX % bound))) {
            *output = r % bound;
            return S2N_RESULT_OK;
        }
    }
}

static int s2n_rand_init_cb_impl(void)
{
    POSIX_GUARD_RESULT(s2n_rand_device_open(&s2n_dev_urandom));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_rand_init(void)
{
    RESULT_ENSURE(s2n_rand_init_cb_impl() >= S2N_SUCCESS, S2N_ERR_CANCELLED);

    return S2N_RESULT_OK;
}

static int s2n_rand_cleanup_cb_impl(void)
{
    POSIX_ENSURE(s2n_dev_urandom.fd != UNINITIALIZED_ENTROPY_FD, S2N_ERR_NOT_INITIALIZED);

    if (s2n_result_is_ok(s2n_rand_device_validate(&s2n_dev_urandom))) {
        POSIX_GUARD(close(s2n_dev_urandom.fd));
    }
    s2n_dev_urandom.fd = UNINITIALIZED_ENTROPY_FD;

    return S2N_SUCCESS;
}

S2N_RESULT s2n_rand_cleanup(void)
{
    RESULT_ENSURE(s2n_rand_cleanup_cb_impl() >= S2N_SUCCESS, S2N_ERR_CANCELLED);

    return S2N_RESULT_OK;
}
