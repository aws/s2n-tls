#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./generate_certs.sh [clean]
# Generates mixed-chain certs for testing
# Use argument "clean" to remove all generated certs

# immediately bail if any command fails
set -e

# Generates certs with given algorithms and bits in $1$2/, ex. ec384/
# $1: rsa or ec
# $2: size of the key used by the leaf and intermediate
# $3: size of the key used by the issuing CA
# $4: digest using in the certificate signatures
# $5: name of the output directory
cert-gen () {
    key_family=$1
    key_size=$2
    ca_key_size=$3
    digest=$4
    dir_name=$5

    echo -e "\n----- generating certs for ec $key_size with $digest $signature -----\n"

    # make directory for certs
    mkdir -p $dir_name
    cd $dir_name

    echo "generating CA private key and certificate"
    openssl req -new -noenc -x509 \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:P-$ca_key_size \
            -keyout  ca-key.pem \
            -out ca-cert.pem \
            -days 65536 \
            -$digest \
            -subj "/C=US/CN=root" \
            -addext "basicConstraints = critical,CA:true" \
            -addext "keyUsage = critical,keyCertSign"

    echo "generating intermediate private key and CSR"
    openssl req  -new -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:P-$key_size \
            -keyout intermediate-key.pem \
            -out intermediate.csr \
            -subj "/C=US/CN=branch" \
            -addext "basicConstraints = critical,CA:true" \
            -addext "keyUsage = critical,keyCertSign"

    echo "generating server private key and CSR"
    openssl req  -new -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:P-$key_size \
            -keyout server-key.pem \
            -out server.csr \
            -subj "/C=US/CN=leaf" \
            -addext "subjectAltName = DNS:localhost"

    echo "generating intermediate certificate and signing it"
    openssl x509 -days 65536 \
            -req -in intermediate.csr \
            -$digest \
            -CA ca-cert.pem \
            -CAkey ca-key.pem \
            -CAcreateserial \
            -out intermediate-cert.pem \
            -copy_extensions=copyall

    echo "generating server certificate and signing it"
    openssl x509 -days 65536 \
            -req -in server.csr \
            -$digest \
            -CA intermediate-cert.pem \
            -CAkey intermediate-key.pem \
            -CAcreateserial -out server-cert.pem \
            -copy_extensions=copyall

    touch server-chain.pem
    cat server-cert.pem >> server-chain.pem
    cat intermediate-cert.pem >> server-chain.pem
    cat ca-cert.pem >> server-chain.pem

    echo "verifying server certificates"
    openssl verify -CAfile ca-cert.pem intermediate-cert.pem
    openssl verify -CAfile ca-cert.pem -untrusted intermediate-cert.pem server-cert.pem

    # certificate signing requests are never used after the certs are generated
    rm server.csr
    rm intermediate.csr

    # serial files are generated during the signing process, but are not used
    rm ca-cert.srl
    rm intermediate-cert.srl

    # the private keys of the CA and the intermediate CA are never needed after 
    # signing
    rm ca-key.pem
    rm intermediate-key.pem

    # the intermediate and server certs are included in server-chain.pem, so 
    # the individual files can be deleted
    rm intermediate-cert.pem
    rm server-cert.pem

    cd ..
}

if [[ $1 != "clean" ]]
then
    #         key   key_size  ca_key_size    digest     directory
    cert-gen   ec     384        256         SHA384      ecdsa
else
    echo "cleaning certs"
    rm -rf ecdsa*
fi
