# Initialization and Teardown

## Initialization
The s2n-tls library must be initialized with `s2n_init()` before calling most library functions. `s2n_init()` will error if it is called more than once, even when an application uses multiple threads.

Initialization can be modified by calling `s2n_crypto_disable_init()` or `s2n_disable_atexit()` before `s2n_init()`.

An application can override s2n-tls’s internal memory management by calling `s2n_mem_set_callbacks()` before calling `s2n_init()`.

## Teardown
### Thread-local Memory
We recommend calling `s2n_cleanup()` from every thread created after `s2n_init()` to ensure there are no memory leaks. s2n-tls has thread-local memory that it attempts to clean up automatically at thread-exit. However, this is done using pthread destructors and may not work if you are using a threads library other than pthreads.

### Library Cleanup
A full cleanup and de-initialization of the library can be done by calling `s2n_cleanup_final()`. s2n-tls allocates some memory at initialization that is intended to live for the duration of the process, but can be cleaned up earlier with `s2n_cleanup_final()`. Not calling this method may cause tools like ASAN or valgrind to detect memory leaks, as the memory will still be allocated when the process exits.
