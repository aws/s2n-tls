# Interop Tests
## Goal
The goal of the tests in this category is to test interoperability with other TLS implementations. 

## Structure
The interop tests are largely inspired by the work done with the [Quic Interop Runner](https://interop.seemann.io). Client and Server implementations are invoked with the name of the scenario under test, and then execute the scenario-specific logic. Clients and Servers communicate with each other in a "request/response" pattern. 

The only available client implementations are
- s2n-tls

And the only server implementation is
- s2n-tls

The interop runner defines a number of test cases. Binaries are invoked with the following arguments
```
client_binary $TEST_CASE $SERVER_PORT
```
```
server_binary $TEST_CASE $SERVER_PORT
```

## Tests
All tests currently use TLS 1.3. Acceptable cipher suites/groups are not specified

- Handshake (`handshake`)
    1. handshake
    2. client initiates graceful TLS closure
- RequestResponse (`request_response`)
    1. handshake
    2. client sends `i am the client. nice to meet you server.`
    3. server responds `i am the server. a pleasure to make your acquaintance.`
    4. client initiates graceful TLS closure
- MTLSRequestResponse (`mtls_request_response`)
    - identical to the "RequestResponse" scenario, but over mutual TLS.
- Large Data Download (`large_data_download`): 
    1. handshake
    2. client sends `i am the client. nice to meet you server.`
    3. server responds with 256 Gb of data. This number is chosen to be higher than the default key update limits that most implementations have set
        - The first byte of each Mb (1,000,000 bytes) is equal to the "Gb's sent". So the first 1,000 Mb have `payload[0] = 0`. The next 1,000 Mb have `payload[0] = 1`, and so on.
    4. client initiates graceful TLS closure
- Large Data Download with Frequent Key Updates (`large_data_download_with_frequent_key_updates`):
    1. handshake
    2. client sends `i am the client. nice to meet you server.`
    3. server responds with 256 Gb of data, identical to the data sent in the `Large Data Download` trial.
    4. server updates it's send key every Gb. This is not a precisely monitored number, but servers should send ~256 Key Updates over the course of this scenario
    5. client initiates graceful TLS closure

### Test Context
The "Large Data Download" cases are motivated by JDK behavior: https://bugs.openjdk.org/browse/JDK-8329548. As of 2024-04-16 the JDK will send a KeyUpdate message for each TLS record that it receives past it's CipherLimit (137 Gb). Typical server implementations won't stop to read those messages until they are finished sending data. This results in a huge number of KeyUpdates exhausting the TCP flow control window, deadlocking the connection and causing the Large Data Download tests to time out and fail. If the server sends a key update before the JDK requests them this behavior can be avoided, so the `Large Data Download With Frequent Key Updates` scenario is expected to pass.

### Future Tests

- Server Initiated Close
- Session Resumption
- Half Close
- Resumption
    - example incompatibility: https://github.com/aws/s2n-tls/issues/4124
- Early Data
- OOB PSK
- Client Hello Retry
    - example incompatibility: https://github.com/rustls/rustls/issues/1373
- Small TCP Packet

## Certificates

Test certificates are available in [interop/certificates](certificates). Clients should trust `ca-certificate.pem`, and servers should send the full `server-chain.pem`.
