# Error Handling

s2n-tls functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n-tls functions that return pointer types return NULL in the case of
failure. When an s2n-tls function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string
explaining the error in English by calling `s2n_strerror(s2n_errno, "EN")`.
A string containing human readable error name, can be generated with `s2n_strerror_name()`.
A string containing internal debug information, including filename and line number, can be generated with `s2n_strerror_debug()`.
This string is useful to include when reporting issues to the s2n-tls development team.

Example:

```
if (s2n_config_set_cipher_preferences(config, prefs) < 0) {
    printf("Setting cipher prefs failed! %s : %s", s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
    return -1;
}
```

**NOTE**: To avoid possible confusion, s2n_errno should be cleared after processing an error: `s2n_errno = S2N_ERR_T_OK`

When using s2n-tls outside of `C`, the address of the thread-local `s2n_errno` may be obtained by calling the `s2n_errno_location()` function.
This will ensure that the same TLS mechanisms are used with which s2n-tls was compiled.

## Error Types

s2n-tls organizes errors into different "types" to allow applications to handle error values without catching all possibilities.
Applications using non-blocking I/O should check the error type to determine if the I/O operation failed because it would block or for some other error. To retrieve the type for a given error use `s2n_error_get_type()`.
Applications should perform any error handling logic using these high level types:

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

Blinding is a mitigation against timing side-channels which in some cases can leak information about encrypted data. [This](https://aws.amazon.com/blogs/security/s2n-and-lucky-13/) blog post includes a good description of blinding and how it mitigates timing side-channels like Lucky13.

By default s2n-tls will cause a thread to sleep between 10 and 30 seconds whenever an error triggered by the peer occurs. The default implementation of blinding blocks the thread.

For non-blocking blinding, an application can handle the delay itself. This is useful for applications that are handling many connections in a single thread. The application should set the `S2N_SELF_SERVICE_BLINDING` option with `s2n_connection_set_blinding()`. After `s2n_recv()` or `s2n_negotiate()` return an error, the application must call `s2n_connection_get_delay()` and pause activity on the connection for the specified number of nanoseconds before calling `s2n_shutdown()`, `close()`, or `shutdown()`. `s2n_shutdown()` will fail if called before the blinding delay elapses. To correctly implement self-service blinding, the application must have nanosecond-level resolution on its implementation of the delay. Not properly implementing self-service blinding (such as by not waiting for the full delay before calling `close()` on the underlying socket) makes an application potentially vulnerable to timing side-channel attacks.

The maximum blinding delay is configurable via `s2n_config_set_max_blinding_delay()`. However, setting a maximum delay lower than the recommended default (30s) will make timing side-channel attacks easier. The lower the delay, the fewer requests and less total time an attacker will need to execute a side-channel attack. If a lower delay is required for reasons such as client timeouts, then the highest value practically possible should be chosen to limit risk. Do not lower the blinding delay without fully understanding the risks.

## Stacktraces
s2n-tls has an mechanism to capture stacktraces when errors occur.
This mechanism is off by default, but can be enabled in code by calling `s2n_stack_traces_enabled_set()`.
It can be enabled globally by setting the environment variable `S2N_PRINT_STACKTRACE=1`.

Call `s2n_print_stacktrace()` to print your stacktrace.

**Note:** Enabling stacktraces can significantly slow down unit tests, causing failures on tests (such as `s2n_cbc_verify`) that measure the timing of events.
