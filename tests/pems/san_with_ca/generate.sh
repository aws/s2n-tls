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
        -SHA256 \
        -subj "/C=US/CN=root" \
        -addext "basicConstraints = critical,CA:true" \
        -addext "keyUsage = critical,keyCertSign"

echo "generating server private key and CSR"
openssl req  -new -noenc \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-384 \
        -keyout kitten-key.pem \
        -out kitten.csr \
        -subj "/C=US/CN=kitten" \
        -addext "subjectAltName = DNS:www.kitten.com"

echo "generating server certificate and signing it"
openssl x509 -days 65536 \
        -req -in kitten.csr \
        -SHA256 \
        -CA ca-cert.pem \
        -CAkey ca-key.pem \
        -CAcreateserial \
        -out kitten-cert.pem \
        -copy_extensions=copyall

touch kitten-chain.pem
cat kitten-cert.pem >> kitten-chain.pem
cat ca-cert.pem >> kitten-chain.pem

echo "verifying server certificates"
openssl verify -CAfile ca-cert.pem kitten-cert.pem

# certificate signing requests are never used after the certs are generated
rm kitten.csr
rm ca-cert.srl

# the private keys of the CA are never needed after signing
rm ca-key.pem
rm ca-cert.pem
rm kitten-cert.pem

