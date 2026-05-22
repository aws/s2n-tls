## Overview
The files in this directory represent a cert hierarchy to test OCSP response stapling.

## CA
- ca_cert.pem
- ca_key.pem

Issuer for all of the other certs in the directory.
Since this is a test PKI, we do an intermediate for issuing leaf cert(s).

## OCSP
* ocsp_cert.pem
* ocsp_key.pem

Cert/key for the test OCSP responder. OCSP responses will be signed by the key.
The CN for this cert matches the URI in the Server Cert's "Authority Information Access" x509 extension.

## Server Cert
* server_cert.pem
* server_key.pem

The leaf cert/key. OCSP responses will be generated for this cert.

### Early Expiry Cert
The `server_cert_early_expire.pem` is a certificate that expires in 2037. This certificate is used to validate correct behavior of expired dates for unit tests on 32 bit platforms. This is necessary because 32 bit `time_t` values can't represent dates past 2038, so our unit tests on 32 bit platforms can't test the expiry of very long lived certs.

This cert and the corresponding ocsp response, `ocsp_response_early_expire.der` can be generated at any time by running the `./generate.sh` script. This will break the `Test OCSP validation at various offsets from update times` unit test, because the "This Update" timestamp of `ocsp_response_early_expire.der` will change.

This is fixed by setting `this_update_timestamp_nanoseconds` in `Test OCSP validation at various offsets from update times` to the new "This Update" timestamp. This can be found with
```
openssl ocsp -respin ocsp_response_early_expire.der -text -noverify | grep "This Update"
```
## OCSP response
* ocsp_response.der

DER formatted OCSP response for the Server Cert. This file will be configured in s2n for stapling.

The OCSP responses can be viewed in plaintext using the `ocsp` command.
```
openssl ocsp -respin ocsp_response_early_expire.der -text -noverify
```

## Generating a new OCSP response for the leaf cert
Should not be necessary. The current response expires in 100 years.

From the current directory:

### Run the server
```
# With nextUpdate
openssl ocsp -port 8889 -text -CA ca_cert.pem \
      -index certs.txt \
      -rkey ocsp_key.pem \
      -rsigner ocsp_cert.pem \
      -nrequest 1 \
      -ndays $(( 365 * 100 ))

# Without nextUpdate
openssl ocsp -port 8890 -text -CA ca_cert.pem \
      -index certs.txt \
      -rkey ocsp_key.pem \
      -rsigner ocsp_cert.pem \
      -nrequest 1
```

### Run the client and save the result to file
```
# With nextUpdate
openssl ocsp -CAfile ca_cert.pem \
      -url http://127.0.0.1:8889 \
      -issuer ca_cert.pem \
      -verify_other ocsp_cert.pem \
      -cert server_cert.pem -respout ocsp_response.der
# Without nextUpdate
openssl ocsp -CAfile ca_cert.pem \
      -url http://127.0.0.1:8890 \
      -issuer ca_cert.pem \
      -verify_other ocsp_cert.pem \
      -cert server_cert.pem -respout ocsp_response_no_next_update.der
```

### Generating ocsp_response_revoked.der
```
# Run responder
openssl ocsp -port 8889 -text -CA ca_cert.pem \
      -index certs_revoked.txt \
      -rkey ocsp_key.pem \
      -rsigner ocsp_cert.pem \
      -nrequest 1 -ndays $(( 365 * 100 ))

# Run requester
openssl ocsp -CAfile ca_cert.pem \
      -url http://127.0.0.1:8889 \
      -issuer ca_cert.pem \
      -cert server_cert.pem \
      -respout ocsp_response_revoked.der
```

### Index Files
The index files in the previous commands are in the CA Database format, and are the source of truth for certificates being verified or rejected.

> The index file consists of zero or more lines, each containing the following fields separated by tab characters:
>
>     Certificate status flag (V=valid, R=revoked, E=expired).
>     Certificate expiration date in YYMMDDHHMMSSZ format.
>     Certificate revocation date in YYMMDDHHMMSSZ[,reason] format. Empty if not revoked.
>     Certificate serial number in hex.
>     Certificate filename or literal string ‘unknown’.
>     Certificate distinguished name.
> -- https://pki-tutorial.readthedocs.io/en/latest/cadb.html
