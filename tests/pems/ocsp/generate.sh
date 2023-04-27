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

# immediately bail if any command fails
set -e

# This script assumes the existence of
# ca_key.pem
# ca_cert.pem
# server_key.pem - the private key for early expiry cert being generated
# config/ca.cnf
# config/server_early_expiry.cnf

echo "generating serial file"
touch config/serial
# the openssl ca command will read this file to figure out the serial number,
# increment it for each certificate that is signed. This is the serial number in
# hex notation.
echo "1024" > config/serial

echo "generating server early expiry CSR"
openssl req  -new -nodes -key server_key.pem -out server_early_expire.csr -config config/server_early_expire.cnf

echo "creating empty CA database"
# it's mandatory for this to exist, although it is initially empty
# this data base will be updated during the ca command
touch certs_early_expire_index.txt

echo "generating server certificate and signing it"
# this directory holds the duplicate certs that the CA command generates
# https://security.stackexchange.com/questions/111448/how-to-avoid-writing-pem-while-signing-a-csr
mkdir -p to_nuke

# use the "batch" option to disable prompting
# the enddate argument is in YYYYMMDDHHMMSS format
# use the "notext" option because s2n can't parse .pem certificates with the
# text information inside of them
openssl ca -batch \
    -in server_early_expire.csr  \
    -out server_cert_early_expire.pem \
    -config config/ca.cnf \
    -outdir to_nuke \
    -enddate 20370101010101Z \
    -extfile config/server_early_expire.cnf \
    -extensions req_ext \
    -notext

echo "verifying generated certificates"
openssl verify -CAfile ca_cert.pem server_cert_early_expire.pem

echo "generating ocsp response"
# This is the target next_update date for the OCSP response. This date needs to
# be before 2038 so that next_update field can be tested on 32 bit platforms.
target_date="2036-01-01"
current_date=$(date +%Y-%m-%d)
expiration_days=$(( ($(date -d "$target_date" +%s) - $(date -d "$current_date" +%s)) / 86400 ))

# The & launches the server in the background
openssl ocsp -port 8889 -text -CA ca_cert.pem \
      -index certs_early_expire_index.txt \
      -rkey ocsp_key.pem \
      -rsigner ocsp_cert.pem \
      -nrequest 1 \
      -ndays $expiration_days \
      &

openssl ocsp -CAfile ca_cert.pem \
      -url http://127.0.0.1:8889 \
      -issuer ca_cert.pem \
      -verify_other ocsp_cert.pem \
      -cert server_cert_early_expire.pem -respout ocsp_response_early_expire.der

echo "removing temporary files"
rm server_early_expire.csr
# openssl generates <file>, <file>.attr, <file>.old, and <file>.attr.old
# delete all of them
rm certs_early_expire_index* -f
rm to_nuke -rf
rm config/serial
rm config/serial.old

