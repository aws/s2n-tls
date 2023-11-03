+++
title = 'Errors and alerts'
date = 2023-10-23T18:57:23-07:00
draft = false
weight = 51
+++

- s2n_errno
- s2n_errno_location()
- s2n_error_get_type()
- s2n_error_type {...}
- S2N_ERR_T_ALERT
- S2N_ERR_T_BLOCKED
- S2N_ERR_T_CLOSED
- S2N_ERR_T_INTERNAL
- S2N_ERR_T_IO
- S2N_ERR_T_OK
- S2N_ERR_T_PROTO
- S2N_ERR_T_USAGE
- s2n_alert_behavior
- s2n_stack_traces_enabled()
- s2n_stack_traces_enabled_set()

If the peer sends an alert, the next call to a read IO method will report **S2N_FAILURE** and `s2n_error_get_type()` will return **S2N_ERR_T_ALERT**. The specific alert received is available by calling `s2n_connection_get_alert()`.

In TLS1.3, all alerts are fatal. s2n-tls also treats all alerts as fatal in earlier
versions of TLS by default. `s2n_config_set_alert_behavior()` can be called to
force s2n-tls to treat pre-TLS1.3 warning alerts as not fatal, but that behavior
is not recommended unless required for compatibility. In the past, attacks against
TLS have involved manipulating the alert level to disguise fatal alerts as warnings.

If s2n-tls encounters a fatal error, the next call to a write IO method will send
a close_notify alert to the peer. Except for a few exceptions, s2n-tls does not
send specific alerts in order to avoid leaking information that could be used for
a sidechannel attack. To ensure that the alert is sent, `s2n_shutdown()` should
be called after an error.

## Error handling

s2n-tls functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n-tls functions that return pointer types return NULL in the case of
failure. When an s2n-tls function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string
explaining the error in English by calling `s2n_strerror(s2n_errno, "EN")`.
A string containing human readable error name, can be generated with `s2n_strerror_name`.
A string containing internal debug information, including filename and line number, can be generated with `s2n_strerror_debug`.
This string is useful to include when reporting issues to the s2n-tls development team.

Example:

```c
if (s2n_config_set_cipher_preferences(config, prefs) < 0) {
    printf("Setting cipher prefs failed! %s : %s", s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
    return -1;
}
```

**NOTE**: To avoid possible confusion, s2n_errno should be cleared after processing an error: `s2n_errno = S2N_ERR_T_OK`

When using s2n-tls outside of `C`, the address of the thread-local `s2n_errno` may be obtained by calling the `s2n_errno_location` function.
This will ensure that the same TLS mechanisms are used with which s2n-tls was compiled.

### Error Types

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
