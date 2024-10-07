# Initialization and Teardown
The s2n-tls library must be initialized with `s2n_init()` before calling most library functions. `s2n_init()` MUST NOT be called more than once, even when an application uses multiple threads or processes. s2n attempts to clean up its thread-local memory at thread-exit and all other memory at process-exit. However, this may not work if you are using a thread library other than pthreads or other threads using s2n outlive the thread that called `s2n_init()`. In that case you should call `s2n_cleanup_thread()` from every thread or process created after `s2n_init()`.

> Note: `s2n_cleanup_thread()` is currently considered unstable, meaning the API is subject to change in a future release. To access this API, include `s2n/unstable/cleanup.h`.

Initialization can be modified by calling `s2n_crypto_disable_init()` or `s2n_disable_atexit()` before `s2n_init()`.

An application can override s2n-tls’s internal memory management by calling `s2n_mem_set_callbacks` before calling s2n_init.

If you are trying to use FIPS mode, you must enable FIPS in your libcrypto library (probably by calling `FIPS_mode_set(1)`) before calling `s2n_init()`.
