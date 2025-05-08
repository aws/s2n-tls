#!/usr/bin/env bash
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

# This script regenerates the Apache certificates with RSA 2048-bit keys
# while preserving all the certificate information.

set -eu

# Common configuration for both certificates
SUBJECT="/C=US/ST=Massachusetts/L=Boston/O=Amazon/OU=s2n/CN=localhost"
DAYS=36500  # 100 years, same as in gen_self_signed_cert.sh

# Generate server certificate
echo "Generating Apache server certificate with RSA 2048-bit key..."
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout apache_server_key.pem -out apache_server_cert.pem \
  -days $DAYS -subj "$SUBJECT"

# Generate client certificate
echo "Generating Apache client certificate with RSA 2048-bit key..."
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout apache_client_key.pem -out apache_client_cert.pem \
  -days $DAYS -subj "$SUBJECT"

echo "Apache certificates have been regenerated with RSA 2048-bit keys."
