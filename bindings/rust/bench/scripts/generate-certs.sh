#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./generate_certs.sh [clean]
# Generates all necessary certs for benching
# Use argument "clean" to remove all generated certs

# immediately bail if any command fails
set -e

# go to directory certs are located
pushd "$(dirname "$0")"/../certs > /dev/null

# Generates certs with given algorithms and bits in $1$2/, ex. ec384/
# $1: rsa or ec
# $2: number of bits
# $3: directory under the `certs/` directory to put certs in
cert-gen () {
    echo -e "\n----- generating certs for $1$2 -----\n"

    key_family=$1
    key_size=$2
    dir_name=$3

    # set openssl argument name
    if [[ $key_family == rsa ]]; then
        local argname=rsa_keygen_bits:
    elif [[ $key_family == ec ]]; then
        local argname=ec_paramgen_curve:P-
    fi

    # make directory for certs
    mkdir -p $dir_name
    cd $dir_name

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
    cert-gen ec 384 ecdsa384
    cert-gen rsa 2048 rsa2048
    cert-gen rsa 3072 rsa3072
    cert-gen rsa 4096 rsa4096
else 
    echo "cleaning certs"
    rm -rf ecdsa*/ rsa*/
fi

popd > /dev/null
