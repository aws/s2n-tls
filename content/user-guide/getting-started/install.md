+++
title = 'Initialization and Teardown'
date = 2023-10-23T19:20:55-07:00
draft = false
weight = 24
+++

- s2n_init()
- s2n_cleanup()
- s2n_crypto_disable_init()
- s2n_disable_atexit()
- s2n_mem_set_callbacks
- FIPS_mode_set(1)

The s2n-tls library must be initialized with `s2n_init()` before calling most library functions. `s2n_init()` MUST NOT be called more than once, even when an application uses multiple threads or processes. s2n attempts to clean up its thread-local memory at thread-exit and all other memory at process-exit. However, this may not work if you are using a thread library other than pthreads. In that case you should call `s2n_cleanup()` from every thread or process created after `s2n_init()`.

Initialization can be modified by calling `s2n_crypto_disable_init()` or `s2n_disable_atexit()` before `s2n_init()`.

An application can override s2n-tls's internal memory management by calling `s2n_mem_set_callbacks` before calling s2n_init.

If you are trying to use FIPS mode, you must enable FIPS in your libcrypto library (probably by calling `FIPS_mode_set(1)`) before calling `s2n_init()`.