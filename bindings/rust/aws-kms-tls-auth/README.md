# aws-kms-tls-auth

This crate provides a way to perform TLS authentication using the AWS Key Management Service (KMS) and Identity and Access Management (IAM). The only supported TLS implementation is currently [s2n-tls](https://github.com/aws/s2n-tls), but if you are interested in support for other TLS implementations please open a [github issue](https://github.com/aws/s2n-tls/issues/new/choose).

## Overview

Clients use the [generateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) API to create a PSK with KMS. The ciphertext datakey is used as the PSK identity, which the server can then [decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html). This PSK exchange is done using the TLS 1.3 out-of-band PSK mechanism. Other TLS protocols are not supported. 

## Description

### 0: setup
We start with 
- clients: all clients are configured with some IAM role, `client-iam-role`
- servers: all servers are configured with some IAM role, `server-iam-role`.
- kms-key-arn: a [KMS Key Arn](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN), which will look like `arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`.
    - `client-iam-role` must have `kms:GenerateDataKey` permissions on the key
    - `server-iam-role` must have `kms:Decrypt` permissions on the key

### 1: client psk generation
When the `PskProvider` is initialized, the client will call the KMS generateDataKey api. This returns both a plaintext data key and a ciphertext datakey. The client will create a PSK using the ciphertext datakey as the PSK identity, and the plaintext datakey as the PSK secret.

### 2: server psk decrypt
The client sends the PSK to the server, which gives it access to the PSK identity (ciphertext datakey). The server then decrypts the ciphertext datakey using KMS, getting back the plaintext datakey which is the actual PSK secret.

At this point the handshake can complete. This results in an mTLS connection between the `client-iam-role` and `server-iam-role`.

### Caching
The server will cache plaintext datakeys. The first connection between a client and server will result in a KMS Decrypt API call, but future TLS handshakes between that same client and server will use the cached key.

### Rotation
The client will automatically rotate its PSK every 24 hours.

## Authentication
When the handshake is complete there is a mutually authenticated connection where 
- the client knows that the server has `kms:Decrypt` permissions on the used KMS Key ARN.
- the server knows that the client has `kms:GenerateDataKey` permissions on one of the trusted KMS Key ARNs.

For this reason, it is important to configure the key with minimal permissions. If you only want mTLS to be allowed between `client-iam-role` as a client and `server-iam-role` as a server, then `client-iam-role` must be the only IAM identity with `kms:GenerateDataKey` permissions on the KMS key, and `server-iam-role` must be the only IAM identity with `kms:Decrypt` permissions on the key.

While it is possible to configure multiple client roles with `kms:GenerateDataKey` permissions so  the server will trust multiple identities, the server will not authenticate the specific client identity.

**Example**: `client-iam-role-A` and `client-iam-role-B` are the only identities with `kms:GenerateDataKey` permissions on a trusted KMS Key ARN. If the server successfully handshakes then it is talking to `client-iam-role-A` OR `client-iam-role-B`, but it does not know which one. 
