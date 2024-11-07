# Initialization and Teardown

## Initialization
The s2n-tls library must be initialized with `s2n_init()` before using the library functions. `s2n_init()` will error if it is called more than once per process.

Initialization can be modified by calling `s2n_crypto_disable_init()` or `s2n_disable_atexit()` before `s2n_init()`.

An application can override s2n-tls’s internal memory management by calling `s2n_mem_set_callbacks` before calling `s2n_init()`.

If you are trying to use FIPS mode, you must enable FIPS in your libcrypto library (probably by calling `FIPS_mode_set(1)`) before calling `s2n_init()`.

## Teardown
### Thread-local Memory
s2n has thread-local memory that it attempts to clean up automatically at thread-exit. This is done using pthread destructors and may not work if you are using a threads library other than pthreads. You can call `s2n_cleanup()` from every thread or process created after `s2n_init()` if you notice thread-local memory leaks.

### Library Cleanup
A full cleanup and de-initialization of the library can be done by calling `s2n_cleanup_final()`.
