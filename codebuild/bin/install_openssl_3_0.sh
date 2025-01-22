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

set -ex
pushd "$(pwd)"

usage() {
    echo "install_openssl_3_0.sh build_dir install_dir os_name [fips]"
    exit 1
}

if [ "$#" -eq "3" ]; then
    FIPS=false
elif [ "$#" -eq "4" ] && [ "$4" = "fips" ]; then
    FIPS=true
else
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
OS_NAME=$3
source codebuild/bin/jobs.sh
config=$(cat codebuild/bin/s2n_fips_openssl.cnf)

# Only some versions of Openssl-3 are FIPS validated.
# The list can be found at https://openssl-library.org/source/
# Maintain separate release versions so that we can change the non-FIPS version
# without worrying about whether or not the new version is FIPS validated.
if $FIPS; then
    RELEASE=3.0.9
else
    RELEASE=3.0.7
fi

mkdir -p $BUILD_DIR
cd "$BUILD_DIR"
curl --retry 3 -L --output OpenSSL_${RELEASE}.zip \
    https://github.com/openssl/openssl/archive/refs/tags/openssl-${RELEASE}.zip
unzip OpenSSL_${RELEASE}.zip
cd openssl-openssl-${RELEASE}

if $FIPS; then
    CONFIGURE="./Configure enable-fips"
else
    CONFIGURE="./Configure"
fi

mkdir -p $INSTALL_DIR
# Use g3 to get debug symbols in libcrypto to chase memory leaks
$CONFIGURE shared -g3 -fPIC              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng no-dtls          \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix="$INSTALL_DIR"

make -j $JOBS
make -j $JOBS test
make -j $JOBS install

popd

# sym-link lib -> lib64 since codebuild assumes /lib path
pushd $INSTALL_DIR
ln -s lib64 lib
popd

# Openssl3 uses the openssl config file to enable fips
# See https://docs.openssl.org/master/man7/fips_module/#making-all-applications-use-the-fips-module-by-default
if $FIPS; then
    # We assume that the configs are in the /ssl directory of $INSTALL_DIR
    pushd $INSTALL_DIR
    config_path=./ssl/openssl.cnf
    # We need an absolute path for the fips config
    fips_config_path=$(pwd)/ssl/fipsmodule.cnf
    config=$(echo "$config" | sed "s,S2N_FIPS_CONFIG_PATH,$fips_config_path,")
    echo "$config" > $config_path
    popd
fi

exit 0
