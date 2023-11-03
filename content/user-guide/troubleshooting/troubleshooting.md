+++
title = 'Monitoring'
date = 2023-10-23T19:16:09-07:00
draft = false
weight = 52
+++

- s2n_stack_traces_enabled()
- s2n_stack_traces_enabled_set()
- Keep on or with errors.md

## Logging

If something goes wrong, we will need the error from the s2n-tls library in order to debug your issue. You should log:

`s2n_strerror_name`: The name of the error. The exact error code may vary between s2n-tls versions, but the name will allow us to identify your error.
`s2n_strerror_debug``: More verbose than the name, but we STRONGLY recommend that you log this. It greatly simplifies debugging. Without this, we often need to reproduce a particular bug you encounter before we can find the root cause, and that can be very difficult if the bug is triggered by specific customer inputs.
`s2n_strerror`: A description of the error. This is optional, but may help you understand the error without engaging the s2n-tls team.

## Monitoring

## Stacktraces

s2n-tls has an mechanism to capture stacktraces when errors occur. This mechanism is off by default, but can be enabled in code by calling `s2n_stack_traces_enabled_set()`. It can be enabled globally by setting the environment variable `S2N_PRINT_STACKTRACE=1`.

Call `s2n_print_stacktrace()` to print your stacktrace.

**Note:** Enabling stacktraces can significantly slow down unit tests, causing failures on tests (such as `s2n_cbc_verify`) that measure the timing of events.

## Testing

s2n-tls provides client and server test applications which are useful for testing your integration. You can find them at https://github.com/aws/s2n-tls/tree/main/bin.

openssl provides similar applications, usually already installed on your system. You can run the client with `openssl s_client` and the server with `openssl s_server`. A list of options are available with the "-help" command.

## Common problems

Every mistake here has been made by at least one team, often by several. Please review this list before running your s2n-tls code in production.

### Not handling errors

Almost all s2n-tls methods can fail, and those failures should be handled and logged. See https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#error-handling.

### Not handling IO errors

Make sure that you review the public examples of how to call s2n-tls IO methods: https://github.com/aws/s2n-tls/tree/main/docs/examples

The `blocked` parameter can be deceptive. `blocked` should only be checked if `s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED`. It should NOT be used in place of the return value to detect failures, and it should NOT be used in place of s2n_error_get_type to determine whether or not an error is fatal. If you only use `blocked`, you will not detect fatal errors. Depending on how you've implemented your event loop, you may then enter an infinite loop.

For example, this is wrong and will not handle fatal errors:

{{ notice warning}}
This code is an example of what not to do! Don't copy this code! 
{{ /notice }}

```c
int bytes_written = 0;
while (blocked == S2N_NOT_BLOCKED) {
    int w = s2n_send(conn, data + bytes_written, data_size - bytes_written, &blocked);
    if (w >= 0) {
        bytes_written += w;
    }
}
```

`blocked` is currently only really useful for s2n_negotiate and s2n_shutdown, not for s2n_send and s2n_recv. That may change in the future if s2n_send can block on anything other than writes or s2n_recv can block on anything other than reads.

### Not calling s2n_shutdown

In order to gracefully close a TLS connection, you must call s2n_shutdown. If you instead simply close the underlying TCP connection, your peer will likely interpret that as an error. Without a graceful shutdown, your peer cannot determine whether you intended to stop sending or whether a malicious actor ended your transmission early. This is called a "truncation attack".

### Disabling certificate validation

s2n-tls offers a method called `s2n_config_disable_x509_verification`` which will completely disable certificate validation. This makes performing handshakes easier, but does not provide any authentication and therefore severely limits the security of TLS. What's the benefit of encryption if you originally negotiated the encryption key with a malicious actor instead of your intended target?

Some teams use `s2n_config_disable_x509_verification`` for testing. We suggest using self-signed test certificates instead. If you choose to use `s2n_config_disable_x509_verification`, make absolutely sure that you never call it from production code.

## Debugging s2n-tls

You're run into a TLS problem, either while testing your integration or in production. What next?

### Error messages

If you followed our logging guidance, then an error should be available in your logs. Check it for hints.

### Reproducing the issue

For handshake failures, often the easiest way to reproduce the problem is to run our test client and server with the same setup. See the testing section.

### Obtaining a packet capture

If you can reproduce the issue or have access to the machine where it is currently occurring, you can try to obtain a packet capture.

There are many ways to obtain a packet capture, but the two easiest are probably:

**Wireshark**. If you need to capture traffic somewhere where you can use a UI, Wireshark is an excellent option. The UI will even display which interfaces are currently receiving traffic to help you select the correct interface to capture on.
**tcpdump**. If you need to capture traffic from the command line, tcpdump is usually installed by default on Linux and MacOS. A basic command would be `sudo tcpdump -i <interface>`. You can list the available interfaces with `tcpdump --list-interfaces`.

In general, you'll want to capture lo / "loopback" if you're communicating with localhost / 127.0.0.1, or eth / en / "Wi-Fi" if you're actually communicating over the network.

If you need to capture on a remote host, you can run something like:

```sh
ADDR=$1
LOGIN=ubuntu
INTERFACE=lo
OUTPUT="output.pcap"

ssh $LOGIN@$ADDR -t "sudo tcpdump -i $INTERFACE -w ~/$OUTPUT"
trap ' ' INT
scp $LOGIN@$ADDR:~/$OUTPUT .
echo "Packet capture available at $OUTPUT"
```

### Decrypting a packet capture

TLS encryption can complicate debugging with a packet capture. In TLS1.3, almost the whole handshake is encrypted.

You can log the encryption keys to a file using options like openssl s_server/s_client's `—keylogfile``, s2nc/s2nd’s `—key-log``, and s2n-tls's `s2n_config_set_key_log_cb`` (do NOT do this in production though!). 

You can then use Wireshark to view the decrypted capture by setting the **Protocol Preferences > TLS > (Pre)-Master-Secret log filename** option. See https://wiki.wireshark.org/TLS#using-the-pre-master-secret.

You can also embed the keys in the packet capture to make the [capture file more portable](https://wiki.wireshark.org/TLS#embedding-decryption-secrets-in-a-pcapng-file)
