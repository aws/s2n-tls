#!/bin/bash
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

set -x 
set -e
BASEDIR=$(pwd)
echo $BASEDIR
S2N_BASE="$BASEDIR/../../../.."
echo $S2N_BASE

cd $BASEDIR
mkdir -p crypto
#The hmac should be based off the old hmac, so just apply the patches to add the invarients
cp $S2N_BASE/crypto/s2n_hmac.c crypto/
cp $S2N_BASE/crypto/s2n_hmac.h crypto/
patch -p5 < ../patches/hmac.patch

#the hash uses my stubs for now, so replace the file
cp ../stubs/s2n_hash.c crypto/
cp ../stubs/s2n_hash.h crypto/

mkdir -p error
cp ../stubs/s2n_errno.c error/

mkdir -p stuffer
cp $S2N_BASE/stuffer/s2n_stuffer.c stuffer/

mkdir -p tls
#add invariants etc needed for the proof to the s2n_cbc code
cp $S2N_BASE/tls/s2n_aead.c tls/
cp $S2N_BASE/tls/s2n_cbc.c tls/
cp $S2N_BASE/tls/s2n_record_read_aead.c tls/
patch -p5 < ../patches/cbc.patch

mkdir -p utils
cp s2n_annotations.h utils/
cp $S2N_BASE/utils/s2n_blob.c utils/
cp $S2N_BASE/utils/s2n_safety.c utils/
cp $S2N_BASE/utils/s2n_safety.h utils/
cp ../stubs/s2n_mem.c utils/
patch -p5 < ../patches/safety1.patch
patch -p5 < ../patches/safety2.patch

cp ../stubs/s2n_annotations.h utils/

