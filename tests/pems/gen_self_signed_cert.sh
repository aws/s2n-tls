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

set -eu

usage() {
    echo "gen_self_signed_cert.sh [OPTION]

Options:
--user-type Server or client depending on intended usage of the cert
--hash-alg The type of hash algorithm to use to sign the cert in openssl format, ex; sha256
--dns A DNS type subject alternative name to add to the cert. Can be repeated.
--ip An IP type subject alternative name to add to the cert. Can be repeated.
--uri A URI type subject alternative name to add to the cert. Can be repeated.
--cn  The CN to add to the cert
--key-type The type of key for the generated certificate to have. Either rsa or ecdsa.
--rsa-key-size Size of rsa key for generated certificate.
--curve-name name of the ECC curve to use for the generated ECDSA certificate.
--prefix Prefix for the output certificate and private key file name. Defaults to the CN value.
"
    exit 0;
}

GETOPT="getopt"

# use gnu-getopt on macos
if [[ "$OSTYPE" == "darwin"* ]]; then
    GETOPT="/usr/local/opt/gnu-getopt/bin/getopt"

    if ! [ -x "$(command -v $GETOPT)" ]; then
      echo 'Error: getopt is not installed. Install with `brew install gnu-getopt`' >&2
      exit 1
    fi
fi

# This only works with gnu getopt.
PARSED_OPTS=`$GETOPT -o vdn: --long help,user-type:,rsa-key-size:,curve-name:,hash-alg:,ip:,uri:,dns:,cn:,key-type:,prefix: -n 'parse-options' -- "$@"`
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
    --cn ) CN="$2" ; shift 2 ;;
    --dns ) SANS="$SANS""DNS:$2,"  ; shift 2 ;;
    --ip ) SANS="$SANS""IP:$2,"  ; shift 2 ;;
    --uri ) SANS="$SANS""URI:$2,"  ; shift 2 ;;
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

config="""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = US
ST = WA
L = Seattle
O = Amazon
OU = s2n
"""

if [[ ! -z "$CN" ]]; then
    config+="CN = $CN"
fi

config+="""

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = $KEY_USAGE
"""

if [[ ! -z "$SANS" ]]; then
    config+="subjectAltName = $SANS"
fi

cert_conf_path=$(mktemp)
echo "$config" > $cert_conf_path

# append an underscore if there's a prefix
if [[ ! -z "$PREFIX" ]]; then
  PREFIX="${PREFIX}_"
fi

if [ "$KEY_TYPE" == "rsa" ]; then
    openssl req -x509 -config "$cert_conf_path" -newkey rsa:${RSA_KEY_SIZE} -${HASH_ALG} -nodes -keyout ${PREFIX}rsa_key.pem -out ${PREFIX}rsa_cert.pem -days 36500
elif [ "$KEY_TYPE" == "ecdsa" ]; then
    openssl ecparam -out "${PREFIX}ecdsa_key.pem" -name "$CURVE_NAME" -genkey
    openssl req -new -config "$cert_conf_path" -days 36500 -nodes -x509 -key "${PREFIX}ecdsa_key.pem" -out "${PREFIX}ecdsa_cert.pem"
else
    echo "Incorrect key-type: $KEY_TYPE"
    usage ;
fi

rm $cert_conf_path

