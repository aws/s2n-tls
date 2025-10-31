# Sending and Receiving Application Data

## Low Level IO

Sending and receiving any data requires reading or writing from the network. s2n-tls offers two ways to handle IO.

### File descriptors

Applications can set file descriptors using s2n_connection_set_fd / s2n_connection_set_read_fd / s2n_connection_set_write_fd.

When an application sets a file descriptor, s2n-tls will configure its IO to call `read` or `write` on that file descriptor when sending or receiving data.

Applications are responsible for opening and configuring the file descriptors. s2n-tls never closes file descriptors, but it does modify them via `setsockopt` in certain cases:

1. Corking. s2n-tls corks and uncorks sockets during the handshake to improve performance. The socket is corked before sending multiple messages, and uncorked once all the messages are ready. See the linux documentation for "TCP_CORK". The state is reset when the connection is wiped.

2. Quickack. s2n-tls disables delayed ACKs. See the linux documentation for "TCP_QUICKACK". This setting is temporary and will reset on its own.

3. kTLS. If an application configures s2n-tls to use kTLS, then s2n-tls will configure the socket to use kTLS. Once enabled, kTLS cannot be disabled.

See [tls/s2n_socket.c](https://github.com/aws/s2n-tls/blob/main/utils/s2n_socket.c) for the file descriptor related logic.

### Custom callbacks

If calling `read` or `write` on a file descriptor is not sufficient, applications can use s2n_connection_set_recv_cb and s2n_connection_set_send_cb to set custom IO callbacks to implement whatever read and write logic they need. These custom callbacks replace the default callbacks set when file descriptors are configured.

Many of s2n-tls's tests take advantage of custom callbacks. For example, unit tests write to stuffers or local memory rather than to the network.

## Records

The primary unit of data in TLS is a "record". Records are composed of a header and a payload. The payload is usually encrypted, except certain messages during the TLS handshake.

When sending or receiving application data, we must read or write that data as encrypted TLS records.

## Fragmentation

TLS records may only contain a limited amount of data. If an application wants to send a larger amount of data, that data will be broken into "fragments" and each fragment will be sent in a separate record.

The maximum fragment length is defined by the TLS protocol as 2^14. s2n-tls uses a default fragment length of about 8k, which a code comment explains as "Testing in the wild has found 8k max record sizes give a good balance of low latency and throughput." Most TLS libraries default to about 16k.

The client and server can use the "Maximum fragment length" extension to negotiate a different fragment length. Lowering the fragment length can improve latency, since each individual record will be faster to process (see [s2n_connection_prefer_low_latency](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#a9b4fafb7e9b8277f408af0ad17ab6e19)). Raising the fragment length can improve throughput, since fewer records will need to be processed (see [s2n_connection_prefer_throughput](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#a11c72914bfc09a9174b6a7b019e5aa5c)).

Changing the fragment length changes how s2n-tls constructs records, but does NOT change how it parses records. s2n-tls will accept record payloads that exceed the negotiated maximum fragment length. Historically TLS implementations have not always respected the negotiated maximum fragment length, so rejecting oversized records could lead to compatibility issues with older TLS libraries.

### Dynamic Record Sizes

s2n-tls also supports a feature where the fragment size starts small and grows to the maximum over a specified period of time. See "[s2n_connection_set_dynamic_record_threshold](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#add5f14855b2810a9857b1a41f2cc92f9)".

## Sending Application Data

To send application data, the customer calls "s2n_send". But when the customer calls s2n_send, what actually happens?

Note: If you are unfamiliar with s2n_send, read [the usage guide](https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch07-io.md#sending-application-data) first. This discussion will assume familiarity with the public usage, behavior, and requirements of s2n_send.

### s2n_sendv and s2n_sendv_with_offset

This document will only refer to "s2n_send", but the explanation still applies to the other send methods. The methods only differ in interface and user experience. "s2n_send" and "s2n_sendv" are just wrappers around "s2n_sendv_with_offset".

### The out buffer

A record is staged in the `out` buffer before being written to the network. Both the headers and the payloads are written to `out`, so it contains complete records. The records are encrypted in-place.

By default, `out` is allocated to the maximum record size given the maximum fragment size, so can only contain a single record at a time. This can be configured: see [Multi-record send](#multi-record-send) below.

### The initial send attempt

The first time the application attempts to send a given chunk of data, the basic process is fairly simple. s2n-tls will break the data into fragments, copy each fragment into the `out` buffer with a record header, encrypt the record, and send the record over the network.

However, if sending any of the records over the network fails, then the call to s2n_send will need to be retried.

### Tracking data sent

To avoid re-sending data already sent when retrying, s2n-tls tracks how much of the currently requested application data has already been sent with the "current_user_data_consumed" field on the connection. 

When s2n-tls blocks on sending application data, the application data falls into three categories:

1. Application data successfully sent.

   If s2n-tls breaks application data into multiple records, then it may encounter a blocking error after some records have already been successfully sent. In that case, it does not return an error. Instead, it returns the size of the data successfully sent.

   The application is responsible for ensuring this data is not re-sent by updating the inputs to their s2n_send call whenever data is successfully sent. For example, if their first call to s2n_send returns `n`, then their next call should be `s2n_send(conn, buf + n, size - n, blocked)`. See [the usage guide](https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch07-io.md#sending-application-data) for a description of how an application should call s2n_send.
   
   The data that was successfully sent will not be counted by "current_user_data_consumed" if a partial send occurs. Before returning, s2n-tls subtracts the size of this data from "current_user_data_consumed". Since the application handles not re-sending this data, s2n-tls will not need to account for it during the next call to s2n_send.

2. Application data waiting in `out`.

   If the call blocked, then there is a record waiting to be sent in the `out` buffer. The application data included in this record is counted by "current_user_data_consumed".

3. Application data not yet touched.

   There may be application data in the application-supplied input buffer that s2n-tls still needs to process into records and send. Since this data has not yet been consumed, it is not counted by "current_user_data_consumed".

Although somewhat complex, this basically results in "current_user_data_consumed" being equivalent to "how much application data is currently waiting in `out`". However, the three categories above better match how the code is actually implemented, so keeping them in mind will make understanding s2n_send easier.

### Continuing after blocking

When an application retries after a blocking error, "current_user_data_consumed" is used to avoid repeating data.

First, a call to "s2n_flush" reattempts writing the data in `out` to the network. If the write is successful, then the s2n_send call continues. "current_user_data_consumed" could therefore be considered "how much application data is currently pending `s2n_flush`".

s2n-tls then continues processing data into records, treating "current_user_data_consumed" as an offset into the application supplied input data buffer.

#### Example

The application calls s2n_send with 300 bytes of data and a maximum fragment size of 100. s2n-tls successfully sends one record, but blocks writing the second record. s2n-tls reports 100 bytes (1 record's worth) successfully sent. Internally, "current_user_data_consumed" is set to 100 bytes to represent the 1 unsent record waiting in `out`.

The application calls s2n_send again, but only with the remaining 200 bytes of data not reported successfully sent. s2n-tls calls s2n_flush again to successfully send the record waiting in `out`. s2n-tls then skips the first current_user_data_consumed=100 bytes of the input array to process the last 100 bytes into a final record. If writing the final record also blocks, then s2n-tls only reports 100 bytes (the flushed record) successfully sent. "current_user_data_consumed" is again set to 100 bytes to represent the final unsent record waiting in `out`.

The application calls s2n_send again, but only with the remaining 100 bytes of data not reported successfully sent. s2n-tls calls s2n_flush again to send the record waiting in `out`. If that send also blocks, then s2n-tls reports a blocking error to the application, since no data was successfully sent.

The application calls s2n_send again, again with the remaining 100 bytes of data. s2n-tls call s2n_flush again, and this time it succeeds. s2n-tls reports the final 100 bytes of data as successfully sent.

### Post-handshake messages

s2n-tls attempts to send any necessary post-handshake messages BEFORE sending any application data. If sending a post-handshake message blocks, the application will be prompted to retry just like if sending the application data had blocked.

### Multi-record send

If the send buffer is configured to be larger than the max record length via [s2n_config_set_send_buffer_size](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#a6de9d794c410474e9851880bd4914025), then s2n_send can buffer more than one record in `out` at a time before writing to the network. This reduces syscalls and can improve performance.

This feature does not signficantly impact the s2n_send logic: it really just makes the call to "s2n_flush" after each record is written to `out` conditional on whether or not there's enough space in `out` for another record.

## Receiving Application Data

To read application data, the customer calls "s2n_recv". But when the customer calls s2n_recv, what actually happens?

Note: If you are unfamiliar with s2n_recv, read [the usage guide](https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch07-io.md#receiving-application-data) first. This discussion will assume familiarity with the public usage, behavior, and requirements of s2n_recv.

### The header_in, in, and buffer_in buffers

Once upon a time, reading a record involved reading the TLS header into the fixed-sized `header_in` buffer and reading the payload into the `in` buffer. The `in` buffer was allocated with enough memory to hold the largest possible record fragment allowed by the RFC. This made `in` generally analagous to `out`, but often larger. If you're trying to understand most of the s2n_recv logic, this is still a useful mental model.

However, in reality, `in` no longer allocates *any* memory. Due to the addition of the "receive buffering" feature, `in` is now just a pointer to a subsection of `buffer_in`, and `buffer_in` is allocated with enough memory to hold the largest possible record allowed by the RFC. This is discussed further in the [Receive Buffering](#receive-buffering) section.

### Reading a record

The basic operation of s2n_recv is fairly simple. First, we read the fixed-sized record header into `header_in`. Then, based on the record size in the header, we read the rest of the record into `in`. The record is decrypted and the plaintext is copied into the output buffer provided by the application.

### Unread data and s2n_peek

When s2n-tls reads a record, that record may contain more data than the application requested. In that case, s2n-tls only returns as much data as the application requested. The rest of the data remains in `in`. When the application calls s2n_recv again, the plaintext waiting in `in` is returned before another record is read.

The "s2n_peek" method can be used to check if any plaintext is waiting in `in`. This method can be used if an application wants to read as much data as possible without triggering another network call.

### Multi-record receive

Historically, s2n_recv only read a single record each time it was called, regardless of how much application data the caller requested. Applications would need to call s2n_recv in a loop to read all expected data. This behavior has been maintained for backwards compatibility.

However, applications can also call [s2n_config_set_recv_multi_record](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#a873c1969c18fdf8663a9b593e62b9460) to instead read records in a loop until the expected amount of application data has been read. This feature does not signficantly impact the s2n_recv logic: it really just wrapped the previous implementation in a loop.

### Receive buffering

By default, s2n-tls reads the record header first, then the record payload. This results in two syscalls per record read. That can make reading small records very expensive.

To improve the performance of reads, an application can call "[s2n_connection_set_recv_buffering](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#ae30791c458875956ef9f4cdbd8c8c19f)" to turn on the "receive buffering" feature. When enabled, s2n-tls will read as much data from the network as possible during each read syscall, potentially reading multiple records in one syscall.

When discussing receive buffering, the simplification that we read records into `header_in` and `in` no longer works.

In reality, we read records into `buffer_in`. The header is then copied into `header_in`, and `in` is initialized to point to the record payload in `buffer_in`. This change allowed us to implement receive buffering without completely rewriting the receive logic. From an interface perspective, `header_in` and `in` still behave as if we read the data into them directly.

When receive buffering is enabled, every read syscall reads as much data as possible into `buffer_in`. We then set `header_in` and `in` to operate on just the first record. Once that record is processed, `header_in` and `in` can be reinitialized to point at the next record. When `buffer_in` doesn't contain enough data for the next record, we shift any remaining data to the beginning of its memory. We then perform another read syscall, reading as much data as we can into `buffer_in` and starting the process over.

