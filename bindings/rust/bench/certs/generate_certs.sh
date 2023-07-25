#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./generate_certs.sh [clean]
# Generates all necessary certs for benching
# Use argument "clean" to remove all generated certs

# immediately bail if any command fails
set -e

# go to directory script is located in
pushd "$(dirname "$0")" > /dev/null

# Generates certs with given algorithms and bits in $1$2/, ex. ec384/
# $1: rsa or ec
# $2: number of bits
cert-gen () {
    echo -e "\n----- generating certs for $1$2 -----\n"

    key_family=$1
    key_size=$2

    # set openssl argument name
    if [[ $key_family == rsa ]]; then
        local argname=rsa_keygen_bits:
    elif [[ $key_family == ec ]]; then
        local argname=ec_paramgen_curve:P-
    fi

    # make directory for certs
    mkdir -p $key_family$key_size
    cd $key_family$key_size

    echo "generating CA private key and certificate"
    openssl req -new -nodes -x509 -newkey $key_family -pkeyopt $argname$key_size -keyout  ca-key.pem -out ca-cert.pem -days 65536 -config ../config/ca.cnf

    echo "generating server private key and CSR"
    openssl req  -new -nodes -newkey $key_family -pkeyopt $argname$key_size -keyout server-key.pem -out server.csr -config ../config/server.cnf

    echo "generating client private key and CSR"
    openssl req  -new -nodes -newkey $key_family -pkeyopt $argname$key_size -keyout client-key.pem -out client.csr -config ../config/client.cnf

    echo "generating server certificate and signing it"
    openssl x509 -days 65536 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extensions req_ext -extfile ../config/server.cnf

    echo "generating client certificate and signing it"
    openssl x509 -days 65536 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -extensions req_ext -extfile ../config/client.cnf

    echo "verifying generated certificates"
    openssl verify -CAfile ca-cert.pem server-cert.pem
    openssl verify -CAfile ca-cert.pem client-cert.pem

    echo "cleaning up temporary files"
    rm server.csr
    rm client.csr
    rm ca-key.pem

    cd ..
}

if [[ $1 != "clean" ]] 
then
    cert-gen ec 384
    cert-gen rsa 2048
    cert-gen rsa 3072
    cert-gen rsa 4096
else 
    echo "cleaning certs"
    rm -rf ec*/ rsa*/
fi

popd > /dev/null
