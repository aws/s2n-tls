#!/bin/bash
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

set -eu

usage() {
    echo "gen_self_signed_cert.sh [OPTION]

Options:
--user-type Server or client depending on intended usage of the cert
--hash-alg The type of hash algorithm to use to sign the cert in openssl format, ex; sha256
--san A DNS type subject alternative name to add to the cert. Can be repeated.
--cn  The CN to add to the cert
--key-type The type of key for the generated certificate to have. Either rsa or ecdsa.
--rsa-key-size Size of rsa key for generated certificate.
--curve-name name of the ECC curve to use for the generated ECDSA certificate.
--prefix Prefix for the output certificate and private key file name. Defaults to the CN value.
"
    exit 0;
}

# This only works with gnu getopt.
PARSED_OPTS=`getopt -o vdn: --long help,user-type:,rsa-key-size:,curve-name:,hash-alg:,san:,cn:,key-type:,prefix: -n 'parse-options' -- "$@"`
eval set -- "$PARSED_OPTS"

USER_TYPE="server"
KEY_TYPE="rsa"
RSA_KEY_SIZE="2048"
CURVE_NAME="prime256v1"
HASH_ALG="sha256"
SANS=
CN="s2nTestCert"
PREFIX=

while true; do
  case "$1" in
    --help ) usage ;;
    # Will be picked up in "cert_config.cfg"
    --cn ) CN="$2" ; shift 2 ;;
    # Will be picked up in "cert_config.cfg"
    --san ) SANS="$SANS""DNS:$2,"  ; shift 2 ;;
    --hash-alg )    HASH_ALG="$2" ; shift 2 ;;
    --key-type ) KEY_TYPE="$2" ; shift 2 ;;
    --rsa-key-size ) RSA_KEY_SIZE="$2" ; shift 2 ;;
    --curve-name ) CURVE_NAME="$2" ; shift 2 ;;
    --user-type ) USER_TYPE="$2" ; shift 2 ;;
    --prefix ) PREFIX="$2" ; shift 2 ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

# Trim the railing comma, openssl x509 config expects the last SAN value to have no comma.
SANS=`echo $SANS | sed 's/,*$//g'`
if [ -z "$PREFIX" ]; then
    PREFIX=$CN
fi

# Picked up by cert_config.cfg. It might have been simpler to just generate all certs with both
# serverAuth and clientAuth KeyUsage.
KEY_USAGE=
if [ "$USER_TYPE" == "server" ]
then
    KEY_USAGE="serverAuth";
elif [ "$USER_TYPE" == "client" ]
then
    KEY_USAGE="clientAuth";
elif [ "$USER_TYPE" == "both" ]
then
    KEY_USAGE="serverAuth, clientAuth";
else
    echo "Incorrect user-type: $USER_TYPE" 
    usage ;
fi

export CN;
export SANS;
export KEY_USAGE;
if [ "$KEY_TYPE" == "rsa" ]; then
    openssl req -x509 -config cert_config.cfg -newkey rsa:${RSA_KEY_SIZE} -${HASH_ALG} -nodes -keyout ${PREFIX}_rsa_key.pem -out ${PREFIX}_rsa_cert.pem -days 36500
elif [ "$KEY_TYPE" == "ecdsa" ]; then
    openssl ecparam -out "${PREFIX}_ecdsa_key.pem" -name "$CURVE_NAME" -genkey
    openssl req -new -config cert_config.cfg -days 36500 -nodes -x509 -key "${PREFIX}_ecdsa_key.pem" -out "${PREFIX}_ecdsa_cert.pem"
else
    echo "Incorrect key-type: $KEY_TYPE"
    usage ;
fi

