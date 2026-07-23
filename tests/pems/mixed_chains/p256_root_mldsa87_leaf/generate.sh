#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Generates a P-256 root -> ML-DSA-87 leaf certificate chain.
# Requires OpenSSL 3.5+ or AWS-LC with ML-DSA support.
#
# Output files:
#   ca-cert.pem       - P-256 self-signed root CA certificate
#   server-key.pem    - ML-DSA-87 leaf private key
#   server-chain.pem  - leaf + root concatenated chain

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "generating P-256 CA private key and certificate"
openssl req -new -noenc -x509 \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-256 \
        -keyout ca-key.pem \
        -out ca-cert.pem \
        -days 65536 \
        -sha256 \
        -subj "/C=US/CN=P256-Root" \
        -addext "basicConstraints = critical,CA:true" \
        -addext "keyUsage = critical,keyCertSign"

echo "generating ML-DSA-87 server key and CSR"
openssl req -new -noenc \
        -newkey ML-DSA-87 \
        -keyout server-key.pem \
        -out server.csr \
        -subj "/C=US/CN=mldsa87-leaf" \
        -addext "subjectAltName = DNS:localhost"

echo "signing ML-DSA-87 leaf with P-256 CA"
openssl x509 -days 65536 \
        -req -in server.csr \
        -sha256 \
        -CA ca-cert.pem \
        -CAkey ca-key.pem \
        -CAcreateserial \
        -out server-cert.pem \
        -copy_extensions=copyall

echo "assembling chain"
cat server-cert.pem > server-chain.pem
cat ca-cert.pem >> server-chain.pem

echo "verifying certificate chain"
openssl verify -CAfile ca-cert.pem server-cert.pem

# cleanup intermediary files
rm -f server.csr ca-cert.srl ca-key.pem server-cert.pem

echo "done. outputs: ca-cert.pem, server-key.pem, server-chain.pem"
