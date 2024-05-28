#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# immediately bail if any command fails
set -e

echo "generating self-signed certificate"
openssl req -new -noenc -x509 \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-384 \
        -keyout  test-key.pem \
        -out test-cert.pem \
        -days 65536 \
        -SHA384 \
        -subj "/C=US/CN=s2n" \
        -addext "basicConstraints = critical,CA:true" \
        -addext "keyUsage = critical,keyCertSign" \
        -addext "subjectAltName = DNS:127.0.0.1"
