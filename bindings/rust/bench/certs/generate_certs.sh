#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# immediately bail if any command fails
set -e

pushd "$(dirname "$0")"

echo "generating CA private key and certificate"
openssl req -nodes -new -x509 -keyout ca-key.pem -out ca-cert.pem -days 65536 -config config/ca.cnf

# secp384r1 is an arbitrarily chosen curve that is supported by the default
# security policy in s2n-tls.
# https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#chart-security-policy-version-to-supported-curvesgroups
echo "generating server private key and CSR"
openssl req  -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout server-key.pem -out server.csr -config config/server.cnf

echo "generating client private key and CSR"
openssl req  -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout client-key.pem -out client.csr -config config/client.cnf

echo "generating server certificate and signing it"
openssl x509 -days 65536 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extensions req_ext -extfile config/server.cnf

echo "generating client certificate and signing it"
openssl x509 -days 65536 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -extensions req_ext -extfile config/client.cnf

echo "verifying generated certificates"
openssl verify -CAfile ca-cert.pem server-cert.pem
openssl verify -CAfile ca-cert.pem client-cert.pem

cat server-cert.pem ca-cert.pem > server-fullchain.pem
cat client-cert.pem ca-cert.pem > client-fullchain.pem

echo "cleaning up temporary files"
rm server.csr
rm client.csr
rm ca-key.pem

popd
