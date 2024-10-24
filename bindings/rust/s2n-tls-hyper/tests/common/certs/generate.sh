# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

echo "generating ec key and cert"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout key.pem -out cert.pem -sha256 -days 36500 -nodes -subj "/C=US/ST=AZ/L=Tempe/O=Amazon/OU=AmazonWebServices/CN=localhost"
