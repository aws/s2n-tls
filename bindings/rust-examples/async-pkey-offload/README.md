# PKey Offload with KMS

This example shows how to use s2n-tls pkey offload functionality to create TLS connections with a private key that is stored in KMS.

It will
1. generate an asymmetric key in KMS
2. create a public (self-signed) x509 certificate corresponding to the private key in KMS
3. handle TLS connections for that certificate, offloading all private key operations to KMS

```  
                          server (s2n-tls)                                   
                          ┌───────────────┐                      KMS         
                          │               │ sign(payload)  ┌─────────────┐   
    Client◄──────────────►│ Public Key    ┼───────────────►│             │   
                  ▲       │ (certificate) │                │ Private Key │   
                  │       │               │◄───────────────┼             │   
                  │       │               │    signature   └─────────────┘   
           TLS Connection └───────────────┘                                  
                                                                             
```

The client will talk to an s2n-tls server. This server only contains the public key in the form of an x509 certificate. The server does _not_ hold a copy of a private key. The only copy of the key is stored in KMS, and it can not be removed from KMS. The advantage of this is that if an attacker were able to compromise the server, they could not steal the private key. 

Because the server does not have a copy of the private key, it must delegate cryptographic operations to KMS, and return those results to the clients. s2n-tls offers a "pkey offload" feature to accomplish this behavior. This example will use s2n-tls pkey offload functionality along with the AWS SDK to successfully complete a TLS handshake with the client, while never actually holding the private key.

### Running the demo
You will need to have access to IAM credentials with KMS permissions to create, list, describe, sign, and delete keys.

Once those are available in the environment, you can run the demo - which is structured as a test - with `cargo test -- --nocapture`.

```
creating new key
Using KMS Key: "b6a9ff77-f672-46a1-8d59-8fa0eb1136ed"
client successfully connected
TlsStream {
    connection: Connection {
        handshake_type: "NEGOTIATED|FULL_HANDSHAKE|MIDDLEBOX_COMPAT",
        cipher_suite: "TLS_AES_128_GCM_SHA256",
        actual_protocol_version: TLS13,
        selected_curve: "secp256r1",
        ..
    },
}
test handshake ... ok
```

You can clean up the test resources by running `cargo run --bin delete_demo_keys`.

### Self Signed Cert Generation
The example will use a self signed cert with an asymmetric key that is stored in KMS. First we generate a private key in KMS. This will be the private key of the certificate. We use [rcgen](https://github.com/rustls/rcgen) and its associated [KeyPair::from_remote](https://docs.rs/rcgen/latest/rcgen/trait.RemoteKeyPair.html) functionality to actually generate the cert. Below you can see what the certificate looked like when I ran it on my own machine.

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            16:5c:dd:a4:d0:01:34:1a:82:16:03:2f:3b:d6:08:95:94:a0:6e:c3
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: CN = rcgen self signed cert
        Validity
            Not Before: Jan  1 00:00:00 1975 GMT
            Not After : Jan  1 00:00:00 4096 GMT
        Subject: CN = rcgen self signed cert
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:d4:40:4c:1a:77:c2:2a:d2:04:f6:11:17:e2:e5:
                    7b:d7:14:9b:47:4a:fb:58:0e:09:a8:7e:c0:45:00:
                    51:55:22:52:1e:51:46:98:e5:57:08:7c:31:36:d5:
                    03:81:21:67:cf:88:75:43:21:c2:91:ec:bb:8f:67:
                    12:76:67:df:44:a0:2f:55:57:af:89:57:66:38:ad:
                    0d:0f:55:bb:2f:70:24:f8:46:67:5e:5b:d0:b5:ba:
                    79:6e:48:a7:f3:c7:9c
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:async-pkey.demo.s2n
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:64:02:30:5f:8d:89:d2:ee:f1:2c:fc:88:43:3b:b4:31:6a:
        7c:61:8e:6a:bb:b3:97:15:68:2d:77:c3:3e:08:c6:48:71:2f:
        2d:ba:96:14:40:f0:66:7d:05:ba:47:27:12:83:d9:78:02:30:
        27:df:5a:73:f6:3a:42:25:e2:7e:e4:e4:65:88:bc:56:98:7a:
        47:92:bd:56:b7:1e:12:44:3a:e4:a1:63:32:f4:35:75:ac:e9:
        94:d6:5d:2b:c5:c4:6d:3b:43:23:a4:b8
```
