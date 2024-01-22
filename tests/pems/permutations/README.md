All of the certs in this directory are generated using the `generate-certs.sh` script included in this directory.

### PKI Structure
```
   ┌────root──────┐
   │              │
   │              │
   ▼              │
 branch           │
   │              │
   │              │
   │              │
   ▼              ▼
 leaf            client
```
`generate-certs.sh` will generate 4 certificates for each key/length/digest selection, with the signing relationships that are indicated in the diagram above. This cert chain length was chosen because it matches the cert chain length used by public AWS services.

### Cert Naming Format
The folder `ecdsa_p521_sha256` indicates that certificates use a p521 ec key, and
that the signature uses a SHA256 hash.

`ec_ecdsa_p384_sha384`
- public key: `secp384r1`
- signature algorithm: `ecdsa-with-SHA384`
```
    Data:
        Version: 3 (0x2)
        Serial Number:
            41:0a:0b:67:a3:dd:fd:fe:a1:58:90:04:db:8d:0a:4e:02:49:3a:e4
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C = US, CN = branch
        Validity
            Not Before: Jan 22 22:05:48 2024 GMT
            Not After : Jun 29 22:05:48 2203 GMT
        Subject: C = US, CN = leaf
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:4e:2a:7f:07:b1:af:00:55:72:2a:72:da:ae:5b:
                    dd:25:4e:d1:0d:26:a8:f1:41:6c:d6:e3:5d:2d:fc:
                    01:23:81:ff:e7:97:ed:9f:d8:d0:67:a6:cd:0f:cf:
                    c9:43:a8:e0:69:b8:71:72:79:51:6c:24:31:37:eb:
                    27:a2:36:ef:b5:d6:f8:0d:80:e0:58:f2:8c:db:fa:
                    7b:e9:ec:6e:41:9f:ec:8d:52:f8:1d:2e:7d:56:8e:
                    03:99:46:99:e8:c8:37
                ASN1 OID: secp384r1
                NIST CURVE: P-384
```

`rsae_pkcs_2048_sha256`
- public key: `rsaEncryption`
- 2048 bit modulus
- signature algorithm: `sha256WithRSAEncryption`, (RSA PKCSv1.5)
```
    Data:
        Version: 3 (0x2)
        Serial Number:
            75:53:05:60:8a:58:f3:8a:da:3a:2d:16:df:66:21:4b:a4:71:a5:1d
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, CN = branch
        Validity
            Not Before: Jan 22 22:05:50 2024 GMT
            Not After : Jun 29 22:05:50 2203 GMT
        Subject: C = US, CN = leaf
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ae:d1:4c:b8:e6:c5:71:6d:c7:ff:f9:f5:49:ce:
                    <SNIP>
```

`rsae_pss_4096_sha384`
- public key: `rsaEncryption`
- 4096 bit modulus
- signature algorithm: `rsassaPss` with `sha384` hash
```
    Data:
        Version: 3 (0x2)
        Serial Number:
            19:49:db:2c:2a:8c:ca:e6:22:cc:a9:f9:95:85:a1:d0:85:2b:4e:12
        Signature Algorithm: rsassaPss
        Hash Algorithm: sha384
        Mask Algorithm: mgf1 with sha384
         Salt Length: 0x30
        Trailer Field: 0x01 (default)
        Issuer: C = US, CN = branch
        Validity
            Not Before: Jan 22 22:06:11 2024 GMT
            Not After : Jun 29 22:06:11 2203 GMT
        Subject: C = US, CN = leaf
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:f6:8f:a5:c5:af:db:47:87:c4:12:bc:dc:43:15:
                    76:ea:32:de:49:38:c9:7d:3f:15:57:3e:ee:fe:23:
                    <SNIP>
```

`rsapss_pss_2048_sha256`
- public key: `rsassaPss`
- 2048 bit modulus
- signature algorithm: `rsassaPss` with `sha256` hash
```
    Data:
        Version: 3 (0x2)
        Serial Number:
            4a:5d:a2:d9:f2:16:79:dc:3d:68:9e:6e:c9:8e:60:17:71:83:df:84
        Signature Algorithm: rsassaPss
        Hash Algorithm: sha256
        Mask Algorithm: mgf1 with sha256
         Salt Length: 0x20
        Trailer Field: 0x01 (default)
        Issuer: C = US, CN = branch
        Validity
            Not Before: Jan 22 22:06:12 2024 GMT
            Not After : Jun 29 22:06:12 2203 GMT
        Subject: C = US, CN = leaf
        Subject Public Key Info:
            Public Key Algorithm: rsassaPss
                Public-Key: (2048 bit)
                Modulus:
                    00:a8:38:39:08:d8:8e:54:17:fb:88:7f:ea:68:a7:
                    3d:04:d5:53:54:c2:da:49:ff:bd:63:0c:f3:9c:09:
                    <SNIP>
```
