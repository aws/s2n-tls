#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./generate_certs.sh [clean]
# Generates all necessary certs for benching
# Use argument "clean" to remove all generated certs

# immediately bail if any command fails
set -e

# Generates certs with given algorithms and bits in $1$2/, ex. ec384/
# $1: rsa or ec
# $2: number of bits
# $3: directory under the `certs/` directory to put certs in
cert-gen () {

    key_family=$1
    signature=$2
    key_size=$3
    digest=$4
    dir_name=$5

    echo -e "\n----- generating certs for $key_family $key_size with $digest $signature -----\n"
    #echo "generating $key_family $key_size cert with $digest $signature"

    # set openssl argument name
    if [[ $key_family == rsa || $key_family == rsa-pss ]]; then
        local argname=rsa_keygen_bits:
    elif [[ $key_family == ec ]]; then
        local argname=ec_paramgen_curve:P-
    fi

    # All signature algorithims are the default except for rsa-pss signatures
    # with rsae keys. For this case we must manually specify things
    if [[ $key_family == rsa && $signature == pss ]]
    then
        local signature_options="-sigopt rsa_padding_mode:pss"
    else
        local signature_options=""
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

    # we pass in the digest here because it is self signed
    echo "generating CA private key and certificate"
    openssl req -new -noenc -x509 \
            -newkey $key_family \
            -pkeyopt $argname$key_size \
            -keyout  ca-key.pem \
            -out ca-cert.pem \
            -days 65536 \
            $signature_options \
            -$digest \
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
            $signature_options \
            -$digest \
            -CA ca-cert.pem \
            -CAkey ca-key.pem \
            -CAcreateserial \
            -out intermediate-cert.pem \
            -copy_extensions=copyall

    echo "generating server certificate and signing it"
    openssl x509 -days 65536 \
            -req -in server.csr \
            $signature_options \
            -$digest \
            -CA intermediate-cert.pem \
            -CAkey intermediate-key.pem \
            -CAcreateserial -out server-cert.pem \
            -copy_extensions=copyall

    echo "generating client certificate and signing it"
    openssl x509 -days 65536 \
            -req -in client.csr \
            $signature_options \
            -$digest \
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

    # certificate signing requests are never used after the certs are generated
    rm server.csr
    rm intermediate.csr
    rm client.csr

    # serial files are generated during the signing process, but are not used
    rm ca-cert.srl
    rm intermediate-cert.srl

    # the private keys of the CA and the intermediat CA are never needed after 
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
    #         key        signature   key_size     digest         directory
    cert-gen   ec          ecdsa       256        SHA256      ec_ecdsa_p256_sha256
    cert-gen   ec          ecdsa       256        SHA384      ec_ecdsa_p256_sha384
    cert-gen   ec          ecdsa       384        SHA256      ec_ecdsa_p384_sha256
    cert-gen   ec          ecdsa       384        SHA384      ec_ecdsa_p384_sha384
    cert-gen   ec          ecdsa       521        SHA384      ec_ecdsa_p521_sha384
    cert-gen   ec          ecdsa       521        SHA512      ec_ecdsa_p521_sha512
    cert-gen   rsa        pkcsv1.5     2048       SHA1        rsae_pkcs_2048_sha1
    cert-gen   rsa        pkcsv1.5     2048       SHA224      rsae_pkcs_2048_sha224
    cert-gen   rsa        pkcsv1.5     2048       SHA256      rsae_pkcs_2048_sha256
    cert-gen   rsa        pkcsv1.5     2048       SHA384      rsae_pkcs_2048_sha384
    cert-gen   rsa        pkcsv1.5     3072       SHA256      rsae_pkcs_3072_sha256
    cert-gen   rsa        pkcsv1.5     3072       SHA384      rsae_pkcs_3072_sha384
    cert-gen   rsa        pkcsv1.5     4096       SHA384      rsae_pkcs_4096_sha384
    cert-gen   rsa          pss        4096       SHA384      rsae_pss_4096_sha384
    cert-gen   rsa-pss      pss        2048       SHA256      rsapss_pss_2048_sha256

else
    echo "cleaning certs"
    rm -rf ecdsa* rsa*
fi
