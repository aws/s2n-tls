#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# immediately bail if any command fails
set -e

echo "generating CA"
openssl req -new -noenc -x509 \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-384 \
        -keyout  ca-key.pem \
        -out ca-cert.pem \
        -days 65536 \
        -SHA384 \
        -subj "/C=US/CN=root" \
        -addext "basicConstraints = critical,CA:true" \
        -addext "keyUsage = critical,keyCertSign"

echo "generating wombat private key and CSR"
openssl req  -new -noenc \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-384 \
        -keyout wombat-key.pem \
        -out wombat.csr \
        -subj "/C=US/CN=wombat" \
        -addext "subjectAltName = DNS:www.wombat.com"

echo "generating kangaroo private key and CSR"
openssl req  -new -noenc \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-384 \
        -keyout kangaroo-key.pem \
        -out kangaroo.csr \
        -subj "/C=US/CN=kangaroo" \
        -addext "subjectAltName = DNS:www.kangaroo.com"

echo "generating wombat server certificate and signing it"
openssl x509 -days 65536 \
        -req -in wombat.csr \
        -SHA384 \
        -CA ca-cert.pem \
        -CAkey ca-key.pem \
        -CAcreateserial \
        -out wombat-cert.pem \
        -copy_extensions=copyall

echo "generating kangaroo certificate and signing it"
openssl x509 -days 65536 \
        -req -in kangaroo.csr \
        -SHA384 \
        -CA ca-cert.pem \
        -CAkey ca-key.pem \
        -CAcreateserial \
        -out kangaroo-cert.pem \
        -copy_extensions=copyall

touch wombat-chain.pem
cat wombat-cert.pem >> wombat-chain.pem
cat ca-cert.pem >> wombat-chain.pem

touch kangaroo-chain.pem
cat kangaroo-cert.pem >> kangaroo-chain.pem
cat ca-cert.pem >> kangaroo-chain.pem

echo "verifying server certificates"
openssl verify -CAfile ca-cert.pem wombat-cert.pem
openssl verify -CAfile ca-cert.pem kangaroo-cert.pem

# certificate signing requests are never used after the certs are generated
rm wombat.csr
rm kangaroo.csr
rm ca-cert.srl

# the private keys of the CA are never needed after signing
rm ca-key.pem
rm wombat-cert.pem
rm kangaroo-cert.pem

