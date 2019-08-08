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

## OCSP response
* ocsp_response.der

DER formatted OCSP response for the Server Cert. This file will be configured in s2n for stapling.

## Generating a new OCSP response for the leaf cert
Should not be necessary. The current response expires in 100 years.

From the current directory:

### Run the server
```
# With nextUpdate
openssl ocsp -port 8889 -text -CA ca_cert.pem \                                                                                                                                                             ocsp_test ✭ ✱ ◼
      -index certs.txt \
      -rkey ocsp_key.pem \
      -rsigner ocsp_cert.pem \
      -nrequest 1 \
      -ndays $(( 365 * 100 ))

# Without nextUpdate
openssl ocsp -port 8890 -text -CA ca_cert.pem \                                                                                                                                                             ocsp_test ✭ ✱ ◼
      -index certs.txt \
      -rkey ocsp_key.pem \
      -rsigner ocsp_cert.pem \
      -nrequest 1
```

### Run the client and save the result to file
```
# With nextUpdate
openssl ocsp -CAfile ca_cert.pem \                                                                                                                                                                          ocsp_test ✭ ✱ ◼
      -url http://127.0.0.1:8889 \
      -issuer ca_cert.pem \
      -verify_other ocsp_cert.pem \
      -cert server_cert.pem -respout ocsp_response.der
# Without nextUpdate
openssl ocsp -CAfile ca_cert.pem \                                                                                                                                                                          ocsp_test ✭ ✱ ◼
      -url http://127.0.0.1:8890 \
      -issuer ca_cert.pem \
      -verify_other ocsp_cert.pem \
      -cert server_cert.pem -respout ocsp_response_no_next_update.der
```

