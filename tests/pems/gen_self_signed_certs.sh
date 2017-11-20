#! /bin/bash
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

USER_TYPES="server client"
RSA_KEY_SIZES="1024 2048 3072 4096"
HASH_ALGS="sha1 sha224 sha256 sha384 sha512"

for user in $USER_TYPES
do
  for rsa_size in $RSA_KEY_SIZES
  do
    for hash_alg in $HASH_ALGS
    do
      PREFIX="rsa_${rsa_size}_${hash_alg}_${user}"
      openssl req -x509 -config cert_config.cfg -newkey rsa:${rsa_size} -${hash_alg} -nodes -keyout ${PREFIX}_key.pem -out ${PREFIX}_cert.pem -days 36500
    done;
  done; 
done;
