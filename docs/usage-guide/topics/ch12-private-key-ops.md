# Offloading Private Key Operations
By default, s2n-tls automatically uses the configured private key to synchronously perform the signature
and decryption operations required for a tls handshake. However, this default behavior may not
work for some situations.

For example:
* An application may want to perform the CPU-expensive signature and decryption operations
asynchronously to avoid blocking the main event loop.
See [Asynchronous private key operations](#asynchronous-private-key-operations)
* An application may not have direct access to the private key, such as when using PKCS#11.
See [Offloading private key operations](#offloading-private-key-operations-1)

To handle these use cases, s2n-tls provides a callback to allow users to control how these operations
are performed. The callback is set via `s2n_config_set_async_pkey_callback()` and is triggered
every time `s2n_negotiate()` performs an action involving the private key. The callback is passed
**op**, an opaque object representing the private key operation. To avoid memory leaks, **op** must
always eventually be freed by calling `s2n_async_pkey_op_free()`.

The private key operation can be performed by calling `s2n_async_pkey_op_perform()`
(or `s2n_async_pkey_op_set_output()`: see [Offloading private key operations](#offloading-private-key-operations-1)).
The required private key can be retrieved using the `s2n_connection_get_selected_cert()` and `s2n_cert_chain_and_key_get_private_key()` calls. The operation can then be finalized with `s2n_async_pkey_op_apply()` to continue the handshake.

## Asynchronous Private Key Operations

When s2n-tls is used in non-blocking mode, private key operations can be completed
asynchronously. This model can be useful to move execution of
CPU-heavy private key operations out of the main
event loop, preventing `s2n_negotiate()` from blocking the loop for a few
milliseconds each time the private key operation needs to be performed.

To handle private key operations asynchronously, return from the callback without calling
`s2n_async_pkey_op_perform()` or `s2n_async_pkey_op_apply()`. Usually the user would do this
by spawning a separate thread to perform **op** and immediately returning **S2N_SUCCESS**
from the callback without waiting for that separate thread to complete. In response,
`s2n_negotiate()` will return **S2N_FAILURE** with an error of type **S2N_ERR_T_BLOCKED**
and **s2n_blocked_status** set to **S2N_BLOCKED_ON_APPLICATION_INPUT**.
All subsequent calls to `s2n_negotiate()` will produce the same result until `s2n_async_pkey_op_apply()`
is called to finalize the **op**.

Note: It is not safe to call multiple functions on the same **conn** or
**op** objects from 2 different threads at the same time. Doing so will
produce undefined behavior. However it is safe to have a call to a
function involving only **conn** at the same time as a call to a
function involving only **op**, as those objects are not coupled with
each other. It is also safe to free **conn** or **op** at any moment with
respective function calls, with the exception that **conn** cannot
be freed inside the `s2n_async_pkey_fn()` callback.

## Synchronous Private Key Operations

Despite the "async" in the function names, private key operations can also be completed synchronously using the callback.
To complete an operation synchronously, simply call `s2n_async_pkey_op_perform()` and `s2n_async_pkey_op_apply()` inside the callback.
If the callback succeeds, the handshake will continue uninterrupted.
If the callback fails, `s2n_negotiate()` will fail with an error of type **S2N_ERR_T_INTERNAL**.

## Offloading Private Key Operations

The `s2n_async_pkey_op_perform()` call used to perform a private key operation requires
direct access to the private key. In some cases, like when using PKCS#11, users may not
have access to the private key. In these cases, we can substitute `s2n_async_pkey_op_set_output()`
for `s2n_async_pkey_op_perform()` to tell s2n-tls the result of the operation rather than
having s2n-tls perform the operation itself.

s2n-tls provides a number of calls to gather the information necessary for
an outside module or library to perform the operation. The application can query the type of private
key operation by calling `s2n_async_pkey_op_get_op_type()`. In order to perform
an operation, the application must ask s2n-tls to copy the operation's input into an
application supplied buffer. The appropriate buffer size can be determined by calling
`s2n_async_pkey_op_get_input_size()`. Once a buffer of the proper size is
allocated, the application can request the input data by calling `s2n_async_pkey_op_get_input()`.
After the operation is completed, the finished output can be copied back to S2N by calling `s2n_async_pkey_op_set_output()`.
Once the output is set, the private key operation can be completed by calling `s2n_async_pkey_op_apply()` as usual.

Offloading can be performed either synchronously or asynchronously. If the offloaded operation
fails synchronously, simply return **S2N_FAILURE** from the callback. If the offloaded operation
fails asynchronously, s2n-tls does not provide a way to communicate that result. Instead,
simply shutdown and cleanup the connection as you would for any other error.
