# Connection Serialization

Connection Serialization allows TLS connection state to be serialized into a byte string. This allows the connection to be transported to a different host or stored to disk.

<div class="warning">
This feature is dangerous. It provides cryptographic material from a TLS session in plaintext. An attacker with access to the serialized connection can decrypt any past and future communications from the connection. Users MUST both encrypt and MAC the contents of the serialized connection to provide secrecy and integrity. 

The simplest way to provide secrecy and integrity is to transport the serialized connection using a protocol like TLS which protects the secrecy and integrity of all transported data.
</div>

## Use Case
Connection Serialization is a feature used to support advanced, exceptional use cases. Most users will not find it useful.

One use case for connection serialization is to enable a more complete TLS offload. Traditional private-key offloading allows the certificate private key to be stored separately from the application server, but connection-serialization TLS offloading allows all TLS materials and TLS configuration to be stored separately from the application server.

### Private Key Offloading
For reference, this is a common private key offloading architecture:
```
 client           application server                  key store     
               ┌─────────────────────────┐                       
┌─────┐        │     s2n-tls config      ┼───────►┌─────────────┐
│     ┼───────►│                         │◄───────┼ private key │
└─────┘        │ public key (x509 chain) │    ▲   └─────────────┘
               └─────────────────────────┘    │                  
                                              │                  
                                  server sends material to sign  
                                  key store returns signature    
```

The client will send TLS handshake bytes (e.g. the Client Hello message) to the application server. The server sends all private key operations to the key store, but the public x509 certificate chain and TLS configuration are still owned by the application server.

### Connection-Serialization TLS Offloading
```
                                        key store           
 client    application server   ┌──────────────────────────┐
                                │     s2n-tls config       │
┌─────┐        ┌─────┐ ────────►│                          │
│     ┼───────►│     │◄─────────┼       private key        │
└─────┘        └─────┘     ▲    │                          │
                           │    │  public key (x509 chain) │
                           │    └──────────────────────────┘
                           │                                
                     server sends handshake bytes           
                     key store returns serialized connection
```
In connection-serialization TLS Offloading, the application server will forward all of the handshake bytes to the key store. For the duration of the handshake, the application server is behaving as an L4 proxy, and doesn't parse any of the TLS protocol. Once the TLS handshake is complete, the key store will call `s2n_connection_serialize()` to serialize the connection to bytes, and send it back to the application server. The application server will then deserialize the connection using `s2n_connection_deserialize()`. At this point, the application server can read and write application data to the client.

In this architecture the application server does not store any TLS certificate material, and it does not own the TLS configuration.

## Usage

To enable connection serialization, applications must first set a serialization version on the config using `s2n_config_set_serialization_version()`. Setting a version prevents forwards-incompatible changes from causing deserialization failures. See [Serialization Version Deployment](ch14-connection-serialization.md#serialization-version-deployment) for more information.

To serialize a connection, applications must first obtain a large enough buffer to store the serialized connection. The size of the serialized connection can be obtained with `s2n_connection_serialization_length()`. The serialized connection can then be written into the buffer with `s2n_connection_serialize()`.

To deserialize the connection, call `s2n_connection_deserialize()`. Note that a serialized connection stores a minimal amount of state. So while the deserialized connection can be used to read and write application data, most handshake information will not be preserved, and connection-level getters may not function normally.

## Serialization Version Deployment
Connection Serialization is backwards compatible, but not forwards compatible. This means that a new version of s2n-tls can deserialize old formats, but an old version of s2n-tls can not deserialize new formats.

The serialization version controls what format is written, and the library version controls what formats can be read. To avoid deserialization failures every host in a fleet should support reading a new format before any hosts begin writing that format.
