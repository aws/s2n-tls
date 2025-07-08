#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

# Generate root CA
openssl req -new -noenc -x509 \
    -newkey rsa \
    -pkeyopt rsa_keygen_bits:2048 \
    -keyout "ca-key.pem" \
    -out "ca-cert.pem" \
    -days 65536 \
    -sha256 \
    -subj "/C=US/CN=root" \
    -addext "basicConstraints = critical,CA:true"

for name in "single_oid" "multiple_oids"; do
    # Generate leaf
    if [ "${name}" = "multiple_oids" ]; then
        openssl req  -new -noenc \
            -newkey rsa \
            -pkeyopt rsa_keygen_bits:2048 \
            -keyout "${name}_key.pem" \
            -out "${name}.csr" \
            -subj "/C=US/CN=localhost" \
            -addext "1.3.187.25240.2=critical,ASN1:UTF8String:hello" \
            -addext "1.3.187.25240.3=critical,ASN1:UTF8String:world"
    else
        openssl req  -new -noenc \
            -newkey rsa \
            -pkeyopt rsa_keygen_bits:2048 \
            -keyout "${name}_key.pem" \
            -out "${name}.csr" \
            -subj "/C=US/CN=localhost" \
            -addext "1.3.187.25240.2=critical,ASN1:UTF8String:hello"
    fi

    openssl x509 -days 65536 \
        -req -in "${name}.csr" \
        -sha256 \
        -CA "ca-cert.pem" \
        -CAkey "ca-key.pem" \
        -CAcreateserial -out "${name}_cert_chain.pem" \
        -copy_extensions=copyall
    
    cat ca-cert.pem >> ${name}_cert_chain.pem
done

rm *.srl
rm *.csr
rm ca-key.pem
