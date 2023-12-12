#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./generate_certs.sh [clean]
# Generates all necessary certs for benching
# Use argument "clean" to remove all generated certs

# immediately bail if any command fails
set -e

# go to directory certs are located
mkdir -p "$(dirname "$0")"/../certs
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

    # The "basicConstraints" and "keyUsage" extensions are necessary for CA
    # certificates that sign other certificates. Normally the openssl x509 tool
    # will ignore the extensions requests in the .csr, but by using the
    # copy_extensions=copyall flag we can pass the extensions from the .csr on
    # to the final public certificate.

    # The advantage of manually specifying the extensions is that there is no
    # dependency on any openssl config files

    echo "generating CA private key and certificate"
    openssl req -new -noenc -x509 \
            -newkey $key_family \
            -pkeyopt $argname$key_size \
            -keyout  ca-key.pem \
            -out ca-cert.pem \
            -days 65536 \
            -subj "/C=US/CN=root" \
            -addext "basicConstraints = critical,CA:true" \
            -addext "keyUsage = critical,keyCertSign"

    echo "generating intermediate private key and CSR"
    openssl req  -new -noenc \
            -newkey $key_family \
            -pkeyopt $argname$key_size \
            -keyout intermediate-key.pem \
            -out intermediate.csr \
            -subj "/C=US/CN=branch" \
            -addext "basicConstraints = critical,CA:true" \
            -addext "keyUsage = critical,keyCertSign"

    echo "generating server private key and CSR"
    openssl req  -new -noenc \
            -newkey $key_family \
            -pkeyopt $argname$key_size \
            -keyout server-key.pem \
            -out server.csr \
            -subj "/C=US/CN=leaf" \
            -addext "subjectAltName = DNS:localhost"

    echo "generating client private key and CSR"
    openssl req  -new -noenc \
            -newkey $key_family \
            -pkeyopt $argname$key_size \
            -keyout client-key.pem \
            -out client.csr \
            -subj "/C=US/CN=client" \
            -addext "subjectAltName = DNS:localhost"

    echo "generating intermediate certificate and signing it"
    openssl x509 -days 65536 \
            -req -in intermediate.csr \
            -CA ca-cert.pem \
            -CAkey ca-key.pem \
            -CAcreateserial \
            -out intermediate-cert.pem \
            -copy_extensions=copyall

    echo "generating server certificate and signing it"
    openssl x509 -days 65536 \
            -req -in server.csr \
            -CA intermediate-cert.pem \
            -CAkey intermediate-key.pem \
            -CAcreateserial -out server-cert.pem \
            -copy_extensions=copyall

    echo "generating client certificate and signing it"
    openssl x509 -days 65536 \
            -req -in client.csr \
            -CA ca-cert.pem \
            -CAkey ca-key.pem \
            -CAcreateserial -out client-cert.pem \
            -copy_extensions=copyall

    touch server-chain.pem
    cat server-cert.pem >> server-chain.pem
    cat intermediate-cert.pem >> server-chain.pem
    cat ca-cert.pem >> server-chain.pem

    echo "verifying server certificates"
    openssl verify -CAfile ca-cert.pem intermediate-cert.pem
    openssl verify -CAfile ca-cert.pem -untrusted intermediate-cert.pem server-cert.pem

    echo "verifying client certificates"
    openssl verify -CAfile ca-cert.pem client-cert.pem

    echo "cleaning up temporary files"
    rm server.csr
    rm intermediate.csr
    rm client.csr
    rm ca-key.pem

    cd ..
}

if [[ $1 != "clean" ]]
then
    cert-gen ec 256 ecdsa256
    cert-gen ec 384 ecdsa384
    cert-gen rsa 2048 rsa2048
    cert-gen rsa 3072 rsa3072
    cert-gen rsa 4096 rsa4096
else
    echo "cleaning certs"
    rm -rf ecdsa*/ rsa*/
fi

popd > /dev/null
