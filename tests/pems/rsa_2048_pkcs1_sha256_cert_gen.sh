# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./generate_certs.sh [clean]
# Use argument "clean" to remove all generated certs

# immediately bail if any command fails
set -e

cert-gen () {
    echo -e "\n----- generating certs for rsa 2048 with SHA256 pkcsv1.5 -----\n"

    # make directory for certs
    mkdir -p rsae_pkcs_2048_sha256
    cd rsae_pkcs_2048_sha256

    # we pass in the digest here because it is self signed
    echo "generating CA private key and certificate"
    openssl req -new -noenc -x509 \
            -newkey rsa \
            -pkeyopt rsa_keygen_bits2048 \
            -keyout  ca-key.pem \
            -out ca-cert.pem \
            -days 60000 \
            -SHA256 \
            -subj "/CN=s2nTestRoot" \
            -addext "basicConstraints = critical,CA:true" \
            -addext "keyUsage = critical,keyCertSign" \
            -addext "subjectKeyIdentifier = hash" \
            -addext "authorityKeyIdentifier = keyid,issuer"

    echo "generating intermediate private key and CSR"
    openssl req  -new -noenc \
            -newkey rsa \
            -pkeyopt rsa_keygen_bits2048 \
            -keyout intermediate-key.pem \
            -out intermediate.csr \
            -subj "/CN=s2nTestIntermediate" \
            -addext "basicConstraints = critical,CA:true" \
            -addext "keyUsage = critical,keyCertSign" \

    echo "generating server private key and CSR"
    openssl req  -new -noenc \
            -newkey rsa \
            -pkeyopt rsa_keygen_bits2048 \
            -keyout server-key.pem \
            -out server.csr \
            -subj "/CN=s2nTestServer" \

    echo "generating intermediate certificate and signing it"
    openssl x509 -days 60000 \
            -req -in intermediate.csr \
            -SHA256 \
            -CA ca-cert.pem \
            -CAkey ca-key.pem \
            -CAcreateserial \
            -out intermediate-cert.pem \
            -copy_extensions=copyall

    echo "generating server certificate and signing it"
    openssl x509 -days 60000 \
            -req -in server.csr \
            -SHA256 \
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
    cert-gen   rsa        pkcsv1.5     2048       SHA256      rsae_pkcs_2048_sha256

else
    echo "cleaning certs"
    rm -rf ecdsa* rsa*
fi

