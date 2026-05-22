# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script will generate all of the certs used for examples and tests in
# the rust bindings crates.

# Used for TLS 1.2 connections.
echo "generating rsa key and cert"
openssl req -x509 -newkey rsa:4096 -keyout key_rsa.pem -out cert_rsa.pem -sha256 -days 36500 -nodes -subj "/C=US/ST=AZ/L=Tempe/O=Maas/OU=BioComputing/CN=localhost"


# Used for TLS 1.3 connections.
echo "generating ec key and cert"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout key.pem -out cert.pem -sha256 -days 36500 -nodes -subj "/C=US/ST=AZ/L=Tempe/O=Amazon/OU=AmazonWebServices/CN=localhost"


# Used for testing IPv6. Includes the localhost IPv6 address as a SAN.
echo "generating localhost IPv6 key and cert"
openssl req -x509 \
    -newkey rsa:2048 \
    -keyout key_localhost_ipv6.pem \
    -out cert_localhost_ipv6.pem \
    -sha256 \
    -days 36500 \
    -nodes \
    -subj "/C=US/ST=MA/L=Boston/O=Amazon/OU=AmazonWebServices/CN=localhost" \
    -addext "subjectAltName = IP:0:0:0:0:0:0:0:1"
