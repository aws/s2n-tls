+++
title = 'API Intro'
date = 2023-10-27T20:17:21-07:00
weight = 21
draft = false
+++

The API exposed by s2n-tls is the set of functions and declarations that are in the [s2n.h](../api/s2n.h) header file. Any functions and declarations that are in the [s2n.h](../api/s2n.h) file are intended to be stable (API and ABI) within major version numbers of s2n-tls releases. Other functions and structures used in s2n-tls internally can not be considered stable and their parameters, names, and sizes may change.

The [VERSIONING.rst](../VERSIONING.rst) document contains more details about s2n's approach to versions and API changes.

## API reference

s2n-tls uses [Doxygen](https://doxygen.nl/index.html) to document its public API. The latest s2n-tls documentation can be found on [GitHub pages](https://aws.github.io/s2n-tls/doxygen/).

Documentation for older versions or branches of s2n-tls can be generated locally. To generate the documentation, install doxygen and run `doxygen docs/doxygen/Doxyfile`. The doxygen documentation can now be found at `docs/doxygen/output/html/index.html`.

Doxygen installation instructions are available at the [Doxygen](https://doxygen.nl/download.html) webpage.

The doxygen documentation should be used in conjunction with this guide.

## Error handling

s2n-tls functions that return 'int' return 0 to indicate success and -1 to indicate failure. s2n-tls functions that return pointer types return NULL in the case of failure. When an s2n-tls function returns a failure, s2n_errno will be set to a value corresponding to the error. This error value can be translated into a string explaining the error in English by calling `s2n_strerror(s2n_errno, "EN")`. A string containing human readable error name, can be generated with `s2n_strerror_name`. A string containing internal debug information, including filename and line number, can be generated with `s2n_strerror_debug`. This string is useful to include when reporting issues to the s2n-tls development team.

Example:

```c
if (s2n_config_set_cipher_preferences(config, prefs) < 0) {
    printf("Setting cipher prefs failed! %s : %s", s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
    return -1;
}
```

**NOTE**: To avoid possible confusion, s2n_errno should be cleared after processing an error: `s2n_errno = S2N_ERR_T_OK`

When using s2n-tls outside of `C`, the address of the thread-local `s2n_errno` may be obtained by calling the `s2n_errno_location` function. This will ensure that the same TLS mechanisms are used with which s2n-tls was compiled.

## Error types

s2n-tls organizes errors into different "types" to allow applications to handle error values without catching all possibilities. Applications using non-blocking I/O should check the error type to determine if the I/O operation failed because it would block or for some other error. To retrieve the type for a given error use `s2n_error_get_type()`. Applications should perform any error handling logic using these high level types:

Here's an example that handles errors based on type:

```c
#define SUCCESS 0
#define FAILURE 1
#define RETRY 2

s2n_errno = S2N_ERR_T_OK;
if (s2n_negotiate(conn, &blocked) < 0) {
    switch(s2n_error_get_type(s2n_errno)) {
        case S2N_ERR_T_BLOCKED:
            /* Blocked, come back later */
            return RETRY;
        case S2N_ERR_T_CLOSED:
            return SUCCESS;
        case S2N_ERR_T_IO:
            handle_io_err(errno);
            return FAILURE;
        case S2N_ERR_T_PROTO:
            handle_proto_err();
            return FAILURE;
        case S2N_ERR_T_ALERT:
            log_alert(s2n_connection_get_alert(conn));
            return FAILURE;
        /* Everything else */
        default:
            log_other_error();
            return FAILURE;
    }
}
```

## Blinding

Blinding is a mitigation against timing side-channels which in some cases can leak information about encrypted data. By default s2n-tls will cause a thread to sleep between 10 and 30 seconds whenever tampering is detected.

Setting the `S2N_SELF_SERVICE_BLINDING` option with `s2n_connection_set_blinding()` turns off this behavior. This is useful for applications that are handling many connections in a single thread. In that case, if `s2n_recv()` or `s2n_negotiate()` return an error, self-service applications must call `s2n_connection_get_delay()` and pause activity on the connection for the specified number of nanoseconds before calling `close()` or `shutdown()`. `s2n_shutdown()` will fail if called before the blinding delay elapses.

## Stacktraces

s2n-tls has an mechanism to capture stacktraces when errors occur. This mechanism is off by default, but can be enabled in code by calling `s2n_stack_traces_enabled_set()`. It can be enabled globally by setting the environment variable `S2N_PRINT_STACKTRACE=1`.

Call `s2n_print_stacktrace()` to print your stacktrace.

**Note:** Enabling stacktraces can significantly slow down unit tests, causing failures on tests (such as `s2n_cbc_verify`) that measure the timing of events.

## Initialization and teardown

The s2n-tls library must be initialized with `s2n_init()` before calling most library functions. `s2n_init()` MUST NOT be called more than once, even when an application uses multiple threads or processes. s2n attempts to clean up its thread-local memory at thread-exit and all other memory at process-exit. However, this may not work if you are using a thread library other than pthreads. In that case you should call `s2n_cleanup()` from every thread or process created after `s2n_init()`.

Initialization can be modified by calling `s2n_crypto_disable_init()` or `s2n_disable_atexit()` before `s2n_init()`.

An application can override s2n-tls's internal memory management by calling `s2n_mem_set_callbacks` before calling s2n_init.

If you are trying to use FIPS mode, you must enable FIPS in your libcrypto library (probably by calling `FIPS_mode_set(1)`) before calling `s2n_init()`.

## Connection

Users will need to create a `s2n_connection` struct to store all of the state necessary for a TLS connection. Call `s2n_connection_new()` to create a new server or client connection. Call `s2n_connection_free()` to free the memory allocated for this struct when no longer needed.

## Connection memory

The connection struct is roughly 4KB with some variation depending on how it is configured. Maintainers of the s2n-tls library carefully consider increases to the size of the connection struct as they are aware some users are memory-constrained.

A connection struct has memory allocated specifically for the TLS handshake. Memory-constrained users can free that memory by calling `s2n_connection_free_handshake()` after the handshake is successfully negotiated. Note that the handshake memory can be reused for another connection if `s2n_connection_wipe()` is called, so freeing it may result in more memory allocations later. Additionally some functions that print information about the handshake may not produce meaningful results after the handshake memory is freed.

The input and output buffers consume the most memory on the connection after the handshake. It may not be necessary to keep these buffers allocated when a connection is in a keep-alive or idle state. Call `s2n_connection_release_buffers()` to wipe and free the `in` and `out` buffers associated with a connection to reduce memory overhead of long-lived connections.

## Connection reuse

Connection objects can be re-used across many connections to reduce memory allocation. Calling `s2n_connection_wipe()` will wipe an individual connection's state and allow the connection object to be re-used for a new TLS connection.

## Connection info

s2n-tls provides many methods to retrieve details about the handshake and connection, such as the parameters negotiated with the peer. For a full list, see our [doxygen guide](https://aws.github.io/s2n-tls/doxygen/).

### Protocol version

s2n-tls provides multiple different methods to get the TLS protocol version of the connection. They should be called after the handshake has completed.

* `s2n_connection_get_actual_protocol_version()`: The actual TLS protocol version negotiated during the handshake. This is the primary value referred to as "protocol_version", and the most commonly used.
* `s2n_connection_get_server_protocol_version()`: The highest TLS protocol version the server supports.
* `s2n_connection_get_client_protocol_version()`: The highest TLS protocol version the client advertised.
